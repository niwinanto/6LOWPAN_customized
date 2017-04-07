obj-m := net_hook.o
all:
		make -C /lib/modules/$(shell uname -r)/build  CPPFLAGS="-I/usr/include/" M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
