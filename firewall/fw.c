#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/************************
 * Firewall module core *
 ************************/
struct class *sysfs_class = NULL; // all devices will register under this class

/* register the base sysfs class */
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

/* cleanup all modules, in order of registration.
 * step parameter can be used to do partial cleanup (in case of failure in init)
 */
static void cleanup_firewall(int step){
    switch (step){
    case 7:
        cleanup_filter();
    case 6:
        cleanup_hosts();
    case 5:
        cleanup_conn_tab();
    case 4:
        cleanup_rules();
    case 3:
        cleanup_stats();
    case 2:
        cleanup_log();
    case 1:
        class_destroy(sysfs_class);
    }
}

/* Load all firewall modules in order */
static int __init firewall_init_function(void) {
    int err = 0;
    if ((err = init_sysfs_class())){
        PERR("sysfs class init failed");
        return err;
    }

    //init log
    if ((err = init_log())){
        PERR("log interface init failed");
        cleanup_firewall(1);
        return err;
    }
    //init stats
    if ((err = init_stats())){
        PERR("stats interface init failed");
        cleanup_firewall(2);
        return err;
    }
    //init rules
    if ((err = init_rules())){
        PERR("rules interface init failed");
        cleanup_firewall(3);
        return err;
    }
    //init conn_tab
    if ((err = init_conn_tab())){
        PERR("rules interface init failed");
        cleanup_firewall(4);
        return err;
    }
    //init hosts
    if ((err = init_hosts())){
        PERR("hosts interface init failed");
        cleanup_firewall(5);
        return err;
    }
    //init filter
    if ((err = init_filter())){
        PERR("filter init failed");
        cleanup_firewall(6);
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "firewall initialized successfully!\n");
#endif
    return 0;
}

/* cleanup all modules */
static void __exit firewall_exit_function(void) {
    cleanup_firewall(7);
}

module_init(firewall_init_function);
module_exit(firewall_exit_function);
