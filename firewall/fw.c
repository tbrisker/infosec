#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/************************
 * Firewall module core *
 ************************/
struct class *sysfs_class = NULL;

static int init_sysfs_class(void){
    sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(sysfs_class)) {
        printk(KERN_ERR "Error creating class");
        return -1;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created class %s\n", sysfs_class->name);
#endif
    return 0;
}

static int __init firewall_init_function(void) {
    int err;
    if ((err = init_filter())){
        printk(KERN_ERR "filter init failed with error %d!\n", err);
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "filter initialized successfully!\n");
#endif
    if ((err = init_stats())){
        printk(KERN_ERR "stats interface init failed with error %d!\n", err);
        cleanup_filter(); //we already initialized the fw, so we need to clean it up
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "stats interface initialized successfully!\n");
#endif
    return 0;
}

static void __exit firewall_exit_function(void) {
    cleanup_stats(3);
    cleanup_filter();
}

module_init(firewall_init_function);
module_exit(firewall_exit_function);
