/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

/*
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 */

#include <net/tcp.h>

#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/module.h>

/* People can turn this off for buggy TCP's found in printers etc. */
int sysctl_tcp_retrans_collapse __read_mostly = 1;

/* People can turn this on to work with those rare, broken TCPs that
 * interpret the window field as a signed quantity.
 */
int sysctl_tcp_workaround_signed_windows __read_mostly = 0;

/* This limits the percentage of the congestion window which we
 * will allow a single TSO frame to consume.  Building TSO frames
 * which are too large can cause TCP streams to be bursty.
 */
int sysctl_tcp_tso_win_divisor __read_mostly = 3;

int sysctl_tcp_mtu_probing __read_mostly = 0;
int sysctl_tcp_base_mss __read_mostly = TCP_BASE_MSS;

/* By default, RFC2861 behavior.  */
int sysctl_tcp_slow_start_after_idle __read_mostly = 1;

int sysctl_tcp_cookie_size __read_mostly = 0; /* TCP_COOKIE_MAX */
EXPORT_SYMBOL_GPL(sysctl_tcp_cookie_size);


/* Account for new data that has been sent to the network. */
static void tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;
    
	tcp_advance_send_head(sk, skb);
	tp->snd_nxt = TCP_SKB_CB(skb)->end_seq;
    
	/* Don't override Nagle indefinitely with F-RTO */
	if (tp->frto_counter == 2)
		tp->frto_counter = 3;
    
	tp->packets_out += tcp_skb_pcount(skb);
	if (!prior_packets)
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
                                  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
}

/* SND.NXT, if window was not shrunk.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 tcp_acceptable_seq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
    
	if (!before(tcp_wnd_end(tp), tp->snd_nxt))
		return tp->snd_nxt;
	else
		return tcp_wnd_end(tp);
}

/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
static __u16 tcp_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;
    
	if (dst) {
		unsigned int metric = dst_metric_advmss(dst);
        
		if (metric < mss) {
			mss = metric;
			tp->advmss = mss;
		}
	}
    
	return (__u16)mss;
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism. */
static void tcp_cwnd_restart(struct sock *sk, struct dst_entry *dst)
{
	struct tcp_sock *tp = tcp_sk(sk);
	s32 delta = tcp_time_stamp - tp->lsndtime;
	u32 restart_cwnd = tcp_init_cwnd(tp, dst);
	u32 cwnd = tp->snd_cwnd;
    
	tcp_ca_event(sk, CA_EVENT_CWND_RESTART);
    
	tp->snd_ssthresh = tcp_current_ssthresh(sk);
	restart_cwnd = min(restart_cwnd, cwnd);
    
	while ((delta -= inet_csk(sk)->icsk_rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tp->snd_cwnd = max(cwnd, restart_cwnd);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_cwnd_used = 0;
}

/* Congestion state accounting after a packet has been sent. */
static void tcp_event_data_sent(struct tcp_sock *tp,
                                struct sk_buff *skb, struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const u32 now = tcp_time_stamp;
    
	if (sysctl_tcp_slow_start_after_idle &&
	    (!tp->packets_out && (s32)(now - tp->lsndtime) > icsk->icsk_rto))
		tcp_cwnd_restart(sk, __sk_dst_get(sk));
    
	tp->lsndtime = now;
    
	/* If it is a reply for ato after last received
	 * packet, enter pingpong mode.
	 */
	if ((u32)(now - icsk->icsk_ack.lrcvtime) < icsk->icsk_ack.ato)
		icsk->icsk_ack.pingpong = 1;
}

/* Account for an ACK we sent. */
static inline void tcp_event_ack_sent(struct sock *sk, unsigned int pkts)
{
	tcp_dec_quickack_mode(sk, pkts);
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void tcp_select_initial_window(int __space, __u32 mss,
                               __u32 *rcv_wnd, __u32 *window_clamp,
                               int wscale_ok, __u8 *rcv_wscale,
                               __u32 init_rcv_wnd)
{
	unsigned int space = (__space < 0 ? 0 : __space);
    
	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (65535 << 14);
	space = min(*window_clamp, space);
    
	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = (space / mss) * mss;
    
	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sysctl_tcp_workaround_signed_windows)
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = space;
    
	(*rcv_wscale) = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window
		 * See RFC1323 for an explanation of the limit to 14
		 */
		space = max_t(u32, sysctl_tcp_rmem[2], sysctl_rmem_max);
		space = min_t(u32, space, *window_clamp);
		while (space > 65535 && (*rcv_wscale) < 14) {
			space >>= 1;
			(*rcv_wscale)++;
		}
	}
    
	/* Set initial window to a value enough for senders starting with
	 * initial congestion window of TCP_DEFAULT_INIT_RCVWND. Place
	 * a limit on the initial window when mss is larger than 1460.
	 */
	if (mss > (1 << *rcv_wscale)) {
		int init_cwnd = TCP_DEFAULT_INIT_RCVWND;
		if (mss > 1460)
			init_cwnd =
			max_t(u32, (1460 * TCP_DEFAULT_INIT_RCVWND) / mss, 2);
		/* when initializing use the value from init_rcv_wnd
		 * rather than the default from above
		 */
		if (init_rcv_wnd)
			*rcv_wnd = min(*rcv_wnd, init_rcv_wnd * mss);
		else
			*rcv_wnd = min(*rcv_wnd, init_cwnd * mss);
	}
    
	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min(65535U << (*rcv_wscale), *window_clamp);
}
EXPORT_SYMBOL(tcp_select_initial_window);

/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cur_win = tcp_receive_window(tp);
	u32 new_win = __tcp_select_window(sk);
    
	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;
    
	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale && sysctl_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));
    
	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;
    
	/* If we advertise zero window, disable fast path. */
	if (new_win == 0)
		tp->pred_flags = 0;
    
	return new_win;
}

/* Packet ECN state for a SYN-ACK */
static inline void TCP_ECN_send_synack(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags &= ~TCPHDR_CWR;
	if (!(tp->ecn_flags & TCP_ECN_OK))
		TCP_SKB_CB(skb)->flags &= ~TCPHDR_ECE;
}

/* Packet ECN state for a SYN.  */
static inline void TCP_ECN_send_syn(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
    
	tp->ecn_flags = 0;
	if (sysctl_tcp_ecn == 1) {
		TCP_SKB_CB(skb)->flags |= TCPHDR_ECE | TCPHDR_CWR;
		tp->ecn_flags = TCP_ECN_OK;
	}
}

static __inline__ void
TCP_ECN_make_synack(struct request_sock *req, struct tcphdr *th)
{
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
}

/* Set up ECN state for a packet on a ESTABLISHED socket that is about to
 * be sent.
 */
static inline void TCP_ECN_send(struct sock *sk, struct sk_buff *skb,
                                int tcp_header_len)
{
	struct tcp_sock *tp = tcp_sk(sk);
    
	if (tp->ecn_flags & TCP_ECN_OK) {
		/* Not-retransmitted data segment: set ECT and inject CWR. */
		if (skb->len != tcp_header_len &&
		    !before(TCP_SKB_CB(skb)->seq, tp->snd_nxt)) {
			INET_ECN_xmit(sk);
			if (tp->ecn_flags & TCP_ECN_QUEUE_CWR) {
				tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
				tcp_hdr(skb)->cwr = 1;
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
			}
		} else {
			/* ACK or retransmitted segment: clear ECT|CE */
			INET_ECN_dontxmit(sk);
		}
		if (tp->ecn_flags & TCP_ECN_DEMAND_CWR)
			tcp_hdr(skb)->ece = 1;
	}
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
static void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;
    
	TCP_SKB_CB(skb)->flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;
    
	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;
    
	TCP_SKB_CB(skb)->seq = seq;
	if (flags & (TCPHDR_SYN | TCPHDR_FIN))
		seq++;
	TCP_SKB_CB(skb)->end_seq = seq;
}

static inline int tcp_urg_mode(const struct tcp_sock *tp)
{
	return tp->snd_una != tp->snd_up;
}

#define OPTION_SACK_ADVERTISE	(1 << 0)
#define OPTION_TS		(1 << 1)
#define OPTION_MD5		(1 << 2)
#define OPTION_WSCALE		(1 << 3)
#define OPTION_COOKIE_EXTENSION	(1 << 4)

struct tcp_out_options {
	u8 options;		/* bit field of OPTION_* */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u8 hash_size;		/* bytes in hash_location */
	u16 mss;		/* 0 to disable */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
	__u8 *hash_location;	/* temporary pointer, overloaded */
};

/* The sysctl int routines are generic, so check consistency here.
 */
static u8 tcp_cookie_size_check(u8 desired)
{
	int cookie_size;
    
	if (desired > 0)
    /* previously specified */
		return desired;
    
	cookie_size = ACCESS_ONCE(sysctl_tcp_cookie_size);
	if (cookie_size <= 0)
    /* no default specified */
		return 0;
    
	if (cookie_size <= TCP_COOKIE_MIN)
    /* value too small, specify minimum */
		return TCP_COOKIE_MIN;
    
	if (cookie_size >= TCP_COOKIE_MAX)
    /* value too large, specify maximum */
		return TCP_COOKIE_MAX;
    
	if (cookie_size & 1)
    /* 8-bit multiple, illegal, fix it */
		cookie_size++;
    
	return (u8)cookie_size;
}

/* Write previously computed TCP options to the packet.
 *
 * Beware: Something in the Internet is very sensitive to the ordering of
 * TCP options, we learned this through the hard way, so be careful here.
 * Luckily we can at least blame others for their non-compliance but from
 * inter-operatibility perspective it seems that we're somewhat stuck with
 * the ordering which we have been using if we want to keep working with
 * those broken things (not that it currently hurts anybody as there isn't
 * particular reason why the ordering would need to be changed).
 *
 * At least SACK_PERM as the first option is known to lead to a disaster
 * (but it may well be that other scenarios fail similarly).
 */
static void tcp_options_write(__be32 *ptr, struct tcp_sock *tp,
                              struct tcp_out_options *opts)
{
	u8 options = opts->options;	/* mungable copy */
    
	/* Having both authentication and cookies for security is redundant,
	 * and there's certainly not enough room.  Instead, the cookie-less
	 * extension variant is proposed.
	 *
	 * Consider the pessimal case with authentication.  The options
	 * could look like:
	 *   COOKIE|MD5(20) + MSS(4) + SACK|TS(12) + WSCALE(4) == 40
	 */
	if (unlikely(OPTION_MD5 & options)) {
		if (unlikely(OPTION_COOKIE_EXTENSION & options)) {
			*ptr++ = htonl((TCPOPT_COOKIE << 24) |
                           (TCPOLEN_COOKIE_BASE << 16) |
                           (TCPOPT_MD5SIG << 8) |
                           TCPOLEN_MD5SIG);
		} else {
			*ptr++ = htonl((TCPOPT_NOP << 24) |
                           (TCPOPT_NOP << 16) |
                           (TCPOPT_MD5SIG << 8) |
                           TCPOLEN_MD5SIG);
		}
		options &= ~OPTION_COOKIE_EXTENSION;
		/* overload cookie hash location */
		opts->hash_location = (__u8 *)ptr;
		ptr += 4;
	}
    
	if (unlikely(opts->mss)) {
		*ptr++ = htonl((TCPOPT_MSS << 24) |
                       (TCPOLEN_MSS << 16) |
                       opts->mss);
	}
    
	if (likely(OPTION_TS & options)) {
		if (unlikely(OPTION_SACK_ADVERTISE & options)) {
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
                           (TCPOLEN_SACK_PERM << 16) |
                           (TCPOPT_TIMESTAMP << 8) |
                           TCPOLEN_TIMESTAMP);
			options &= ~OPTION_SACK_ADVERTISE;
		} else {
			*ptr++ = htonl((TCPOPT_NOP << 24) |
                           (TCPOPT_NOP << 16) |
                           (TCPOPT_TIMESTAMP << 8) |
                           TCPOLEN_TIMESTAMP);
		}
		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	}
    
	/* Specification requires after timestamp, so do it now.
	 *
	 * Consider the pessimal case without authentication.  The options
	 * could look like:
	 *   MSS(4) + SACK|TS(12) + COOKIE(20) + WSCALE(4) == 40
	 */
	if (unlikely(OPTION_COOKIE_EXTENSION & options)) {
		__u8 *cookie_copy = opts->hash_location;
		u8 cookie_size = opts->hash_size;
        
		/* 8-bit multiple handled in tcp_cookie_size_check() above,
		 * and elsewhere.
		 */
		if (0x2 & cookie_size) {
			__u8 *p = (__u8 *)ptr;
            
			/* 16-bit multiple */
			*p++ = TCPOPT_COOKIE;
			*p++ = TCPOLEN_COOKIE_BASE + cookie_size;
			*p++ = *cookie_copy++;
			*p++ = *cookie_copy++;
			ptr++;
			cookie_size -= 2;
		} else {
			/* 32-bit multiple */
			*ptr++ = htonl(((TCPOPT_NOP << 24) |
                            (TCPOPT_NOP << 16) |
                            (TCPOPT_COOKIE << 8) |
                            TCPOLEN_COOKIE_BASE) +
                           cookie_size);
		}
        
		if (cookie_size > 0) {
			memcpy(ptr, cookie_copy, cookie_size);
			ptr += (cookie_size / 4);
		}
	}
    
	if (unlikely(OPTION_SACK_ADVERTISE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
                       (TCPOPT_NOP << 16) |
                       (TCPOPT_SACK_PERM << 8) |
                       TCPOLEN_SACK_PERM);
	}
    
	if (unlikely(OPTION_WSCALE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
                       (TCPOPT_WINDOW << 16) |
                       (TCPOLEN_WINDOW << 8) |
                       opts->ws);
	}
    
	if (unlikely(opts->num_sack_blocks)) {
		struct tcp_sack_block *sp = tp->rx_opt.dsack ?
        tp->duplicate_sack : tp->selective_acks;
		int this_sack;
        
		*ptr++ = htonl((TCPOPT_NOP  << 24) |
                       (TCPOPT_NOP  << 16) |
                       (TCPOPT_SACK <<  8) |
                       (TCPOLEN_SACK_BASE + (opts->num_sack_blocks *
                                             TCPOLEN_SACK_PERBLOCK)));
        
		for (this_sack = 0; this_sack < opts->num_sack_blocks;
		     ++this_sack) {
			*ptr++ = htonl(sp[this_sack].start_seq);
			*ptr++ = htonl(sp[this_sack].end_seq);
		}
        
		tp->rx_opt.dsack = 0;
	}
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
static unsigned tcp_syn_options(struct sock *sk, struct sk_buff *skb,
                                struct tcp_out_options *opts,
                                struct tcp_md5sig_key **md5) {
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_cookie_values *cvp = tp->cookie_values;
	unsigned remaining = MAX_TCP_OPTION_SPACE;
	u8 cookie_size = (!tp->rx_opt.cookie_out_never && cvp != NULL) ?
    tcp_cookie_size_check(cvp->cookie_desired) :
    0;
    
#ifdef CONFIG_TCP_MD5SIG
	*md5 = tp->af_specific->md5_lookup(sk, sk);
	if (*md5) {
		opts->options |= OPTION_MD5;
		remaining -= TCPOLEN_MD5SIG_ALIGNED;
	}
#else
	*md5 = NULL;
#endif
    
	/* We always get an MSS option.  The option bytes which will be seen in
	 * normal data packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so that
	 * calculations in tcp_sendmsg are simpler etc.  So account for this
	 * fact here if necessary.  If we don't do this correctly, as a
	 * receiver we won't recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK rules correctly.
	 * SACKs don't matter, we never delay an ACK when we have any of those
	 * going out.  */
	opts->mss = tcp_advertise_mss(sk);
	remaining -= TCPOLEN_MSS_ALIGNED;
    
	if (likely(sysctl_tcp_timestamps && *md5 == NULL)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when;
		opts->tsecr = tp->rx_opt.ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(sysctl_tcp_window_scaling)) {
		opts->ws = tp->rx_opt.rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(sysctl_tcp_sack)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!(OPTION_TS & opts->options)))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}
    
	/* Note that timestamps are required by the specification.
	 *
	 * Odd numbers of bytes are prohibited by the specification, ensuring
	 * that the cookie is 16-bit aligned, and the resulting cookie pair is
	 * 32-bit aligned.
	 */
	if (*md5 == NULL &&
	    (OPTION_TS & opts->options) &&
	    cookie_size > 0) {
		int need = TCPOLEN_COOKIE_BASE + cookie_size;
        
		if (0x2 & need) {
			/* 32-bit multiple */
			need += 2; /* NOPs */
            
			if (need > remaining) {
				/* try shrinking cookie to fit */
				cookie_size -= 2;
				need -= 4;
			}
		}
		while (need > remaining && TCP_COOKIE_MIN <= cookie_size) {
			cookie_size -= 4;
			need -= 4;
		}
		if (TCP_COOKIE_MIN <= cookie_size) {
			opts->options |= OPTION_COOKIE_EXTENSION;
			opts->hash_location = (__u8 *)&cvp->cookie_pair[0];
			opts->hash_size = cookie_size;
            
			/* Remember for future incarnations. */
			cvp->cookie_desired = cookie_size;
            
			if (cvp->cookie_desired != cvp->cookie_pair_size) {
				/* Currently use random bytes as a nonce,
				 * assuming these are completely unpredictable
				 * by hostile users of the same system.
				 */
				get_random_bytes(&cvp->cookie_pair[0],
                                 cookie_size);
				cvp->cookie_pair_size = cookie_size;
			}
            
			remaining -= need;
		}
	}
	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Set up TCP options for SYN-ACKs. */
static unsigned tcp_synack_options(struct sock *sk,
                                   struct request_sock *req,
                                   unsigned mss, struct sk_buff *skb,
                                   struct tcp_out_options *opts,
                                   struct tcp_md5sig_key **md5,
                                   struct tcp_extend_values *xvp)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	unsigned remaining = MAX_TCP_OPTION_SPACE;
	u8 cookie_plus = (xvp != NULL && !xvp->cookie_out_never) ?
    xvp->cookie_plus :
    0;
    
#ifdef CONFIG_TCP_MD5SIG
	*md5 = tcp_rsk(req)->af_specific->md5_lookup(sk, req);
	if (*md5) {
		opts->options |= OPTION_MD5;
		remaining -= TCPOLEN_MD5SIG_ALIGNED;
        
		/* We can't fit any SACK blocks in a packet with MD5 + TS
		 * options. There was discussion about disabling SACK
		 * rather than TS in order to fit in better with old,
		 * buggy kernels, but that was deemed to be unnecessary.
		 */
		ireq->tstamp_ok &= !ireq->sack_ok;
	}
#else
	*md5 = NULL;
#endif
    
	/* We always send an MSS option. */
	opts->mss = mss;
	remaining -= TCPOLEN_MSS_ALIGNED;
    
	if (likely(ireq->wscale_ok)) {
		opts->ws = ireq->rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(ireq->tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when;
		opts->tsecr = req->ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(ireq->sack_ok)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!ireq->tstamp_ok))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}
    
	/* Similar rationale to tcp_syn_options() applies here, too.
	 * If the <SYN> options fit, the same options should fit now!
	 */
	if (*md5 == NULL &&
	    ireq->tstamp_ok &&
	    cookie_plus > TCPOLEN_COOKIE_BASE) {
		int need = cookie_plus; /* has TCPOLEN_COOKIE_BASE */
        
		if (0x2 & need) {
			/* 32-bit multiple */
			need += 2; /* NOPs */
		}
		if (need <= remaining) {
			opts->options |= OPTION_COOKIE_EXTENSION;
			opts->hash_size = cookie_plus - TCPOLEN_COOKIE_BASE;
			remaining -= need;
		} else {
			/* There's no error return, so flag it. */
			xvp->cookie_out_never = 1; /* true */
			opts->hash_size = 0;
		}
	}
	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
static unsigned tcp_established_options(struct sock *sk, struct sk_buff *skb,
                                        struct tcp_out_options *opts,
                                        struct tcp_md5sig_key **md5) {
	struct tcp_skb_cb *tcb = skb ? TCP_SKB_CB(skb) : NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned size = 0;
	unsigned int eff_sacks;
    
#ifdef CONFIG_TCP_MD5SIG
	*md5 = tp->af_specific->md5_lookup(sk, sk);
	if (unlikely(*md5)) {
		opts->options |= OPTION_MD5;
		size += TCPOLEN_MD5SIG_ALIGNED;
	}
#else
	*md5 = NULL;
#endif
    
	if (likely(tp->rx_opt.tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcb ? tcb->when : 0;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}
    
	eff_sacks = tp->rx_opt.num_sacks + tp->rx_opt.dsack;
	if (unlikely(eff_sacks)) {
		const unsigned remaining = MAX_TCP_OPTION_SPACE - size;
		opts->num_sack_blocks =
        min_t(unsigned, eff_sacks,
              (remaining - TCPOLEN_SACK_BASE_ALIGNED) /
              TCPOLEN_SACK_PERBLOCK);
		size += TCPOLEN_SACK_BASE_ALIGNED +
        opts->num_sack_blocks * TCPOLEN_SACK_PERBLOCK;
	}
    
	return size;
}

/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
                            gfp_t gfp_mask)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned tcp_options_size, tcp_header_size;
	struct tcp_md5sig_key *md5;
	struct tcphdr *th;
	int err;
    
	BUG_ON(!skb || !tcp_skb_pcount(skb));
    
	/* If congestion control is doing timestamping, we must
	 * take such a timestamp before we potentially clone/copy.
	 */
	if (icsk->icsk_ca_ops->flags & TCP_CONG_RTT_STAMP)
		__net_timestamp(skb);
    
	if (likely(clone_it)) {
		if (unlikely(skb_cloned(skb)))
			skb = pskb_copy(skb, gfp_mask);
		else
			skb = skb_clone(skb, gfp_mask);
		if (unlikely(!skb))
			return -ENOBUFS;
	}
    
	inet = inet_sk(sk);
	tp = tcp_sk(sk);
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));
    
	if (unlikely(tcb->flags & TCPHDR_SYN))
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &md5);
	else
		tcp_options_size = tcp_established_options(sk, skb, &opts,
                                                   &md5);
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);
    
	if (tcp_packets_in_flight(tp) == 0) {
		tcp_ca_event(sk, CA_EVENT_TX_START);
		skb->ooo_okay = 1;
	} else
		skb->ooo_okay = 0;
    
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);
	skb_set_owner_w(skb, sk);
    
	/* Build TCP header and checksum it. */
	th = tcp_hdr(skb);
	th->source		= inet->inet_sport;
	th->dest		= inet->inet_dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(tp->rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
                                    tcb->flags);
    
	if (unlikely(tcb->flags & TCPHDR_SYN)) {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	} else {
		th->window	= htons(tcp_select_window(sk));
	}
	th->check		= 0;
	th->urg_ptr		= 0;
    
	/* The urg_mode check is necessary during a below snd_una win probe */
	if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			th->urg_ptr = htons(0xFFFF);
			th->urg = 1;
		}
	}
    
	tcp_options_write((__be32 *)(th + 1), tp, &opts);
	if (likely((tcb->flags & TCPHDR_SYN) == 0))
		TCP_ECN_send(sk, skb, tcp_header_size);
    
#ifdef CONFIG_TCP_MD5SIG
	/* Calculate the MD5 hash, as we have all we need now */
	if (md5) {
		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		tp->af_specific->calc_md5_hash(opts.hash_location,
                                       md5, sk, NULL, skb);
	}
#endif
    
	icsk->icsk_af_ops->send_check(sk, skb);
    
	if (likely(tcb->flags & TCPHDR_ACK))
		tcp_event_ack_sent(sk, tcp_skb_pcount(skb));
    
	if (skb->len != tcp_header_size)
		tcp_event_data_sent(tp, skb, sk);
    
	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
                      tcp_skb_pcount(skb));
    
	err = icsk->icsk_af_ops->queue_xmit(skb);
	if (likely(err <= 0))
		return err;
    
	tcp_enter_cwr(sk, 1);
    
	return net_xmit_eval(err);
}

/* This routine just queues the buffer for sending.
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
    
	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

/* Initialize TSO segments for a packet. */
static void tcp_set_skb_tso_segs(struct sock *sk, struct sk_buff *skb,
                                 unsigned int mss_now)
{
	if (skb->len <= mss_now || !sk_can_gso(sk) ||
	    skb->ip_summed == CHECKSUM_NONE) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		skb_shinfo(skb)->gso_segs = 1;
		skb_shinfo(skb)->gso_size = 0;
		skb_shinfo(skb)->gso_type = 0;
	} else {
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now);
		skb_shinfo(skb)->gso_size = mss_now;
		skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	}
}

/* When a modification to fackets out becomes necessary, we need to check
 * skb is counted to fackets_out or not.
 */
static void tcp_adjust_fackets_out(struct sock *sk, struct sk_buff *skb,
                                   int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);
    
	if (!tp->sacked_out || tcp_is_reno(tp))
		return;
    
	if (after(tcp_highest_sack_seq(tp), TCP_SKB_CB(skb)->seq))
		tp->fackets_out -= decr;
}

/* Pcount in the middle of the write queue got changed, we need to do various
 * tweaks to fix counters
 */
static void tcp_adjust_pcount(struct sock *sk, struct sk_buff *skb, int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);
    
	tp->packets_out -= decr;
    
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		tp->sacked_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
		tp->retrans_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
		tp->lost_out -= decr;
    
	/* Reno case is special. Sigh... */
	if (tcp_is_reno(tp) && decr > 0)
		tp->sacked_out -= min_t(u32, tp->sacked_out, decr);
    
	tcp_adjust_fackets_out(sk, skb, decr);
    
	if (tp->lost_skb_hint &&
	    before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(tp->lost_skb_hint)->seq) &&
	    (tcp_is_fack(tp) || (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)))
		tp->lost_cnt_hint -= decr;
    
	tcp_verify_left_out(tp);
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
int tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
                 unsigned int mss_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	int nlen;
	u8 flags;
    
	if (WARN_ON(len > skb->len))
		return -EINVAL;
    
	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;
    
	if (skb_cloned(skb) &&
	    skb_is_nonlinear(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;
    
	/* Get a new skb... force flag on. */
	buff = sk_stream_alloc_skb(sk, nsize, GFP_ATOMIC);
	if (buff == NULL)
		return -ENOMEM; /* We'll just try again later. */
    
	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;
    
	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;
    
	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->flags;
	TCP_SKB_CB(skb)->flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;
    
	if (!skb_shinfo(skb)->nr_frags && skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Copy and checksum data tail into the new buffer. */
		buff->csum = csum_partial_copy_nocheck(skb->data + len,
                                               skb_put(buff, nsize),
                                               nsize, 0);
        
		skb_trim(skb, len);
        
		skb->csum = csum_block_sub(skb->csum, buff->csum, len);
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_split(skb, buff, len);
	}
    
	buff->ip_summed = skb->ip_summed;
    
	/* Looks stupid, but our code really uses when of
	 * skbs, which it never sent before. --ANK
	 */
	TCP_SKB_CB(buff)->when = TCP_SKB_CB(skb)->when;
	buff->tstamp = skb->tstamp;
    
	old_factor = tcp_skb_pcount(skb);
    
	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(sk, skb, mss_now);
	tcp_set_skb_tso_segs(sk, buff, mss_now);
    
	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - tcp_skb_pcount(skb) -
        tcp_skb_pcount(buff);
        
		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
	}
    
	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk);
    
	return 0;
}

/* This is similar to __pskb_pull_head() (it will go to core/skbuff.c
 * eventually). The difference is that pulled data not copied, but
 * immediately discarded.
 */
static void __pskb_trim_head(struct sk_buff *skb, int len)
{
	int i, k, eat;
    
	eat = len;
	k = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (skb_shinfo(skb)->frags[i].size <= eat) {
			put_page(skb_shinfo(skb)->frags[i].page);
			eat -= skb_shinfo(skb)->frags[i].size;
		} else {
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];
			if (eat) {
				skb_shinfo(skb)->frags[k].page_offset += eat;
				skb_shinfo(skb)->frags[k].size -= eat;
				eat = 0;
			}
			k++;
		}
	}
	skb_shinfo(skb)->nr_frags = k;
    
	skb_reset_tail_pointer(skb);
	skb->data_len -= len;
	skb->len = skb->data_len;
}

/* Remove acked data from a packet in the transmit queue. */
int tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	if (skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;
    
	/* If len == headlen, we avoid __skb_pull to preserve alignment. */
	if (unlikely(len < skb_headlen(skb)))
		__skb_pull(skb, len);
	else
		__pskb_trim_head(skb, len - skb_headlen(skb));
    
	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;
    
	skb->truesize	     -= len;
	sk->sk_wmem_queued   -= len;
	sk_mem_uncharge(sk, len);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
    
	/* Any change of skb->len requires recalculation of tso
	 * factor and mss.
	 */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(sk, skb, tcp_current_mss(sk));
    
	return 0;
}

/* Calculate MSS. Not accounting for SACKs here.  */
int tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;
    
	/* Calculate base mss without TCP options:
     It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);
    
	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;
    
	/* Now subtract optional transport overhead */
	mss_now -= icsk->icsk_ext_hdr_len;
    
	/* Then reserve room for full set of TCP options and 8 bytes of data */
	if (mss_now < 48)
		mss_now = 48;
    
	/* Now subtract TCP options size, not including SACKs */
	mss_now -= tp->tcp_header_len - sizeof(struct tcphdr);
    
	return mss_now;
}

/* Inverse of above */
int tcp_mss_to_mtu(struct sock *sk, int mss)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mtu;
    
	mtu = mss +
    tp->tcp_header_len +
    icsk->icsk_ext_hdr_len +
    icsk->icsk_af_ops->net_header_len;
    
	return mtu;
}

/* MTU probing init per socket */
void tcp_mtup_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
    
	icsk->icsk_mtup.enabled = sysctl_tcp_mtu_probing > 1;
	icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp + sizeof(struct tcphdr) +
    icsk->icsk_af_ops->net_header_len;
	icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, sysctl_tcp_base_mss);
	icsk->icsk_mtup.probe_size = 0;
}
EXPORT_SYMBOL(tcp_mtup_init);

/* This function synchronize snd mss to current pmtu/exthdr set.
 
 tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
 for TCP options, but includes only bare TCP header.
 
 tp->rx_opt.mss_clamp is mss negotiated at connection setup.
 It is minimum of user_mss and mss received with SYN.
 It also does not include TCP options.
 
 inet_csk(sk)->icsk_pmtu_cookie is last pmtu, seen by this function.
 
 tp->mss_cache is current effective sending mss, including
 all tcp options except for SACKs. It is evaluated,
 taking into account current pmtu, but never exceeds
 tp->rx_opt.mss_clamp.
 
 NOTE1. rfc1122 clearly states that advertised MSS
 DOES NOT include either tcp or ip options.
 
 NOTE2. inet_csk(sk)->icsk_pmtu_cookie and tp->mss_cache
 are READ ONLY outside this function.		--ANK (980731)
 */
unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;
    
	if (icsk->icsk_mtup.search_high > pmtu)
		icsk->icsk_mtup.search_high = pmtu;
    
	mss_now = tcp_mtu_to_mss(sk, pmtu);
	mss_now = tcp_bound_to_half_wnd(tp, mss_now);
    
	/* And store cached results */
	icsk->icsk_pmtu_cookie = pmtu;
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
	tp->mss_cache = mss_now;
    
	return mss_now;
}
EXPORT_SYMBOL(tcp_sync_mss);

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 */
unsigned int tcp_current_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned header_len;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5;
    
	mss_now = tp->mss_cache;
    
	if (dst) {
		u32 mtu = dst_mtu(dst);
		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_sync_mss(sk, mtu);
	}
    
	header_len = tcp_established_options(sk, NULL, &opts, &md5) +
    sizeof(struct tcphdr);
	/* The mss_cache is sized based on tp->tcp_header_len, which assumes
	 * some common options. If this is an odd packet (because we have SACK
	 * blocks etc) then our calculated header_len will be different, and
	 * we have to adjust mss_now correspondingly */
	if (header_len != tp->tcp_header_len) {
		int delta = (int) header_len - tp->tcp_header_len;
		mss_now -= delta;
	}
    
	return mss_now;
}

/* Congestion window validation. (RFC2861) */
static void tcp_cwnd_validate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
    
	if (tp->packets_out >= tp->snd_cwnd) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_time_stamp;
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out;
        
		if (sysctl_tcp_slow_start_after_idle &&
		    (s32)(tcp_time_stamp - tp->snd_cwnd_stamp) >= inet_csk(sk)->icsk_rto)
			tcp_cwnd_application_limited(sk);
	}
}

/* Returns the portion of skb which can be sent right away without
 * introducing MSS oddities to segment boundaries. In rare cases where
 * mss_now != mss_cache, we will request caller to create a small skb
 * per input skb which could be mostly avoided here (if desired).
 *
 * We explicitly want to create a request for splitting write queue tail
 * to a small skb for Nagle purposes while avoiding unnecessary modulos,
 * thus all the complexity (cwnd_len is always MSS multiple which we
 * return whenever allowed by the other factors). Basically we need the
 * modulo only when the receiver window alone is the limiting factor or
 * when we would be allowed to send the split-due-to-Nagle skb fully.
 */
static unsigned int tcp_mss_split_point(struct sock *sk, struct sk_buff *skb,
                                        unsigned int mss_now, unsigned int cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 needed, window, cwnd_len;
    
	window = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
	cwnd_len = mss_now * cwnd;
    
	if (likely(cwnd_len <= window && skb != tcp_write_queue_tail(sk)))
		return cwnd_len;
    
	needed = min(skb->len, window);
    
	if (cwnd_len <= needed)
		return cwnd_len;
    
	return needed - needed % mss_now;
}

/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int tcp_cwnd_test(struct tcp_sock *tp,
                                         struct sk_buff *skb)
{
	u32 in_flight, cwnd;
    
	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->flags & TCPHDR_FIN) && tcp_skb_pcount(skb) == 1)
		return 1;
    
	in_flight = tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd)
		return (cwnd - in_flight);
    
	return 0;
}

/* Initialize TSO state of a skb.
 * This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
static int tcp_init_tso_segs(struct sock *sk, struct sk_buff *skb,
                             unsigned int mss_now)
{
	int tso_segs = tcp_skb_pcount(skb);
    
	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		tcp_set_skb_tso_segs(sk, skb, mss_now);
		tso_segs = tcp_skb_pcount(skb);
	}
	return tso_segs;
}

/* Minshall's variant of the Nagle send check. */
static inline int tcp_minshall_check(const struct tcp_sock *tp)
{
	return after(tp->snd_sml, tp->snd_una) &&
    !after(tp->snd_sml, tp->snd_nxt);
}

/* Return 0, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized.
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_NODELAY was set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
static inline int tcp_nagle_check(const struct tcp_sock *tp,
                                  const struct sk_buff *skb,
                                  unsigned mss_now, int nonagle)
{
	return skb->len < mss_now &&
    ((nonagle & TCP_NAGLE_CORK) ||
     (!nonagle && tp->packets_out && tcp_minshall_check(tp)));
}

/* Return non-zero if the Nagle test allows this packet to be
 * sent now.
 */
static inline int tcp_nagle_test(struct tcp_sock *tp, struct sk_buff *skb,
                                 unsigned int cur_mss, int nonagle)
{
	/* Nagle rule does not apply to frames, which sit in the middle of the
	 * write_queue (they have no chances to get new data).
	 *
	 * This is implemented in the callers, where they modify the 'nonagle'
	 * argument based upon the location of SKB in the send queue.
	 */
	if (nonagle & TCP_NAGLE_PUSH)
		return 1;
    
	/* Don't use the nagle rule for urgent data (or for the final FIN).
	 * Nagle can be ignored during F-RTO too (see RFC4138).
	 */
	if (tcp_urg_mode(tp) || (tp->frto_counter == 2) ||
	    (TCP_SKB_CB(skb)->flags & TCPHDR_FIN))
		return 1;
    
	if (!tcp_nagle_check(tp, skb, cur_mss, nonagle))
		return 1;
    
	return 0;
}

/* Does at least the first segment of SKB fit into the send window? */
static inline int tcp_snd_wnd_test(struct tcp_sock *tp, struct sk_buff *skb,
                                   unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;
    
	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;
    
	return !after(end_seq, tcp_wnd_end(tp));
}

/* This checks if the data bearing packet SKB (usually t