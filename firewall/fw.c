#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/************************
 * Firewall module core *
 ************************/

static int __init firewall_init_function(void) {
    int err;
    if ((err = init_firewall())){
        printk(KERN_ERR "Firewall init failed with error %d!\n", err);
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "Firewall initialized successfully!\n");
#endif
    if ((err = init_sysfs())){
        printk(KERN_ERR "sysfs interface init failed with error %d!\n", err);
        cleanup_firewall(); //we already initialized the fw, so we need to clean it up
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "sysfs interface initialized successfully!\n");
#endif
    return 0;
}

static void __exit firewall_exit_function(void) {
    cleanup_sysfs(3);
    cleanup_firewall();
}

module_init(firewall_init_function);
module_exit(firewall_exit_function);
