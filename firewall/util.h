#ifndef _UTIL_H_
#define _UTIL_H_

int init_device(const char * name){
#ifdef DEBUG
    printk(KERN_DEBUG "Initializing " name " device...\n");
#endif
    //create char device
    major_number = register_chrdev(0, name, &fops);
    if (major_number < 0){
        printk(KERN_ERR "Error registering chrdev\n");
        return major_number;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "Registered chardev %u\n", major_number);
#endif

    //create stats class
    sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(sysfs_class)) {
        printk(KERN_ERR "Error creating class\n");
        cleanup_stats(1);
        return -1;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created class %s\n", sysfs_class->name);
#endif

    //set the default dev attrs so we don't have to manually add and clean them up
    sysfs_class->dev_attrs = sysfs_attributes;

    //create stats device
    sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, name);
    if (IS_ERR(sysfs_device)) {
        printk(KERN_ERR "Error creating device\n");
        cleanup_stats(2);
        return -2;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created device %s\n", dev_name(sysfs_device));
#endif
    return 0;
}

void cleanup_device(const char *name, int step){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up " name ", step %d\n", step);
#endif
    switch (step){
        case 3:
            device_destroy(sysfs_class, MKDEV(major_number, 0));
        case 2:
            class_destroy(sysfs_class);
        case 1:
            unregister_chrdev(major_number, name);
    }
}


#endif
