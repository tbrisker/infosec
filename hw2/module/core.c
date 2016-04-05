#include "firewall.h"
#include "fw_interface.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/**********/
/*  CORE  */
/**********/
static int __init hw2_init_function(void) {
    int err;
    if ((err = init_firewall())){
        printk(KERN_WARNING "Firewall init failed with error %d!\n", err);
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "Firewall initialized successfully!\n");
#endif
    if ((err = init_sysfs())){
        printk(KERN_WARNING "sysfs interface init failed with error %d!\n", err);
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
