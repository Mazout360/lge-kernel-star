cmd_drivers/staging/zcache/built-in.o :=  ../../arm-eabi-4.6/bin/arm-eabi-ld -EL    -r -o drivers/staging/zcache/built-in.o drivers/staging/zcache/zcache.o ; scripts/mod/modpost drivers/staging/zcache/built-in.o