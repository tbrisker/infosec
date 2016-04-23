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
        return PTR_ERR(sysfs_class);
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created class %s\n", sysfs_class->name);
#endif
    return 0;
}

static void cleanup_firewall(int step){
    switch (step){
    case 5:
        cleanup_filter();
    case 4:
        //cleanup_rules();
    case 3:
        cleanup_stats();
    case 2:
        //cleanup_log();
    case 1:
        class_destroy(sysfs_class);
    }
}

static int __init firewall_init_function(void) {
    int err = 0;
    if ((err = init_sysfs_class())){
        PERR("sysfs class init failed");
        return err;
    }

    //init log
    //init stats
    if ((err = init_stats())){
        PERR("stats interface init failed");
        cleanup_firewall(1);
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "stats interface initialized successfully!\n");
#endif
    //init rules
    //init filter
    if ((err = init_filter())){
        PERR("filter init failed");
        cleanup_firewall(3);
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "filter initialized successfully!\n");
#endif
    return 0;
}


static void __exit firewall_exit_function(void) {
    cleanup_firewall(5);
}

module_init(firewall_init_function);
module_exit(firewall_exit_function);
