obj-m := firewall.o
firewall-objs := fw.o fw_filter.o fw_stats.o fw_log.o fw_rules.o util.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) EXTRA_CFLAGS=-DDEBUG modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
