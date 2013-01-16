cmd_lib/lzo/built-in.o :=  ../../arm-eabi-4.6/bin/arm-eabi-ld -EL    -r -o lib/lzo/built-in.o lib/lzo/lzo_compress.o lib/lzo/lzo_decompress.o ; scripts/mod/modpost lib/lzo/built-in.o
