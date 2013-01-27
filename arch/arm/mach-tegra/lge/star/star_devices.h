#include <linux/proc_fs.h>
#include <linux/switch.h>

#include <mach/hardware.h>

#include <mach-tegra/gpio-names.h>

/*
***************************************************************************************************
*                                       SPI Poweroff
***************************************************************************************************
*/

int is_modem_connected(void)
{
#define GPIO_SUB_DET_N  TEGRA_GPIO_PX5
    int modem_exist;
    static int init = 1;

    if (init)
    {
        tegra_gpio_enable(GPIO_SUB_DET_N);
        gpio_request_one(GPIO_SUB_DET_N, GPIOF_IN, "sub_modem_detect");
        init = 0;
    }

    if (0 == gpio_get_value(GPIO_SUB_DET_N))
    {
        // Modem exist
        modem_exist = 1;
    }
    else
    {
        // Modem is not exist
        modem_exist = 0;
    }
    //gpio_free(GPIO_SUB_DET_N);

    //printk(KERN_INFO "%s : Detecting modem : %d\n", __func__, modem_exist);
    return modem_exist;
}

