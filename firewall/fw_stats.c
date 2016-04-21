#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/******************************/
/*  Firewall stats interface  */
/******************************/

/* variables to hold various needed structs and identifiers. */
static int major_number;
static struct class* stats_class = NULL;
static struct device* stats_device = NULL;
static struct file_operations fops = {
    .owner = THIS_MODULE
};

/* Handler function for displaying a certain attribute.
 * gets the counter from the firewall matching the attribute name first letter.
 */
static ssize_t display(struct device *dev, struct device_attribute *attr, char *buf){
#ifdef DEBUG
    printk(KERN_DEBUG "displaying %s\n", attr->attr.name);
#endif
    return scnprintf(buf, PAGE_SIZE, "%u\n", get_counter(attr->attr.name[0]));
    return -1;
}

/* Handler function for the reset attribute.
 * If it is passed a 0 it resets the counters, otherwise it does nothing.
 */
static ssize_t reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    int temp;
    if (sscanf(buf, "%u", &temp) == 1 && temp == 0){
#ifdef DEBUG
        printk(KERN_DEBUG "Reseting counters.\n");
#endif
        reset_counters();
    }
    return count;
}

/* Array of device attributes to set for the device.
 * We make use of the class dev_attrs pointer to have all the attributes
 * created automatically when the device is created instead of handling this
 * manually and having to clean up if something fails.
 * This takes advantage of the device_add_attributes() "private" function that
 * is called indirectly during device_create().
 */
static struct device_attribute stats_attributes[5]= {
        __ATTR(total, S_IRUSR, display, NULL),
        __ATTR(blocked, S_IRUSR, display, NULL),
        __ATTR(passed, S_IRUSR, display, NULL),
        __ATTR(reset, S_IWUSR, NULL, reset),
        __ATTR_NULL // stopping condition for loop in device_add_attributes()
    };

int init_stats(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Initializing stats device...\n");
#endif
    //create char device
    major_number = register_chrdev(0, DEVICE_NAME_STATS, &fops);
    if (major_number < 0){
        printk(KERN_ERR "Error registering chrdev");
        return major_number;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "Registered chardev %u\n", major_number);
#endif

    //create stats class
    stats_class = class_create(THIS_MODULE, STATS_CLASS);
    if (IS_ERR(stats_class)) {
        printk(KERN_ERR "Error creating class");
        cleanup_stats(1);
        return -1;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created class %s\n", stats_class->name);
#endif

    //set the default dev attrs so we don't have to manually add and clean them up
    stats_class->dev_attrs = stats_attributes;

    //create stats device
    stats_device = device_create(stats_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME_STATS);
    if (IS_ERR(stats_device)) {
        printk(KERN_ERR "Error creating device");
        cleanup_stats(2);
        return -2;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created device %s\n", dev_name(stats_device));
#endif
    return 0;
}

void cleanup_stats(int step){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up stats, step %d\n", step);
#endif
    switch (step){
        case 3:
            device_destroy(stats_class, MKDEV(major_number, 0));
        case 2:
            class_destroy(stats_class);
        case 1:
            unregister_chrdev(major_number, DEVICE_NAME_STATS);
    }
}
