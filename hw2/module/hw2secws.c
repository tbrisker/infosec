#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "firewall.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");


/**********/
/*  CORE  */
/**********/
static int __init hw2_init_function(void) {
    int err;
    if ((err = init_firewall())){
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "Firewall initialized successfully!\n");
#endif
    if ((err = init_sysfs())){
        cleanup_firewall();
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "sysfs interface initialized successfully!\n");
#endif
    return 0;
}

static void __exit hw2_exit_function(void) {
    cleanup_sysfs(3);
    cleanup_firewall();
}

module_init(hw2_init_function);
module_exit(hw2_exit_function);
