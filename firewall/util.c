#include "fw.h"

/* These two methods are copied from drivers/base/core.c, so that our module
 * can easily add and remove a list of attributes to a device instead of
 * doing it one attribute at a time.
 */

static int device_add_attributes(struct device *dev,
                 struct device_attribute *attrs)
{
    int error = 0;
    int i;

    if (attrs) {
        for (i = 0; attr_name(attrs[i]); i++) {
            error = device_create_file(dev, &attrs[i]);
            if (error)
                break;
        }
        if (error)
            while (--i >= 0)
                device_remove_file(dev, &attrs[i]);
    }
    return error;
}

static void device_remove_attributes(struct device *dev,
                     struct device_attribute *attrs)
{
    int i;

    if (attrs)
        for (i = 0; attr_name(attrs[i]); i++)
            device_remove_file(dev, &attrs[i]);
}


int safe_device_init(const char *name, const struct file_operations *fops,
                     struct device *dev, struct device_attribute *attrs){
    //register the device
    int major_number = register_chrdev(0, name, fops);
    if (major_number < 0){
        printk(KERN_ERR "Error registering chrdev\n");
        return major_number;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "Registered chardev %u\n", major_number);
#endif

    //create the device
    dev = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, name);
    if (IS_ERR(dev)) {
        printk(KERN_ERR "Error creating device\n");
        safe_device_cleanup(major_number, 1, NULL, NULL);
        return -1;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created device %s\n", dev_name(dev));
#endif

    if (device_add_attributes(dev, attrs)){
        printk(KERN_ERR "Error adding attributes\n");
        safe_device_cleanup(major_number, 2, NULL, NULL);
        return -2;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "registered device attributes for device %s\n", dev_name(dev));
#endif
    return major_number;
}

void safe_device_cleanup(int major_number, int step, struct device *dev,
                         struct device_attribute *attrs){
    switch (step){
        case 3:
            device_remove_attributes(dev, attrs);
        case 2:
            device_destroy(sysfs_class, MKDEV(major_number, 0));
        case 1:
            unregister_chrdev(major_number, NULL); //we don't really need a name here
    }
}
