obj-m := fw.o
fw-objs := hw2secws.o fw_interface.o firewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) EXTRA_CFLAGS=-DDEBUG modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
