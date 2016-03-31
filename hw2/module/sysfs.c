#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "firewall.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/***********/
/*  Sysfs  */
/***********/


#define CHARDEV_NAME "stats"
#define CLASS_NAME "FW_interface"
static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static struct file_operations fops = {
    .owner = THIS_MODULE
};

static ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)   //sysfs show implementation
{
#ifdef DEBUG
    printk(KERN_DEBUG "displaying %s\n", attr->attr.name);
#endif
    return scnprintf(buf, PAGE_SIZE, "%u\n", get_counter(attr->attr.name[0]));
    return -1;
}

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

static struct device_attribute stats_attributes[5]= {
        __ATTR(total, S_IRUSR, display, NULL),
        __ATTR(blocked, S_IRUSR, display, NULL),
        __ATTR(passed, S_IRUSR, display, NULL),
        __ATTR(reset, S_IWUSR, NULL, reset),
        __ATTR_NULL
    };

extern int cleanup_sysfs(int step){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up sysfs, step %d\n", step);
#endif
    switch (step){
        case 3:
            device_destroy(sysfs_class, MKDEV(major_number, 0));
        case 2:
            class_destroy(sysfs_class);
        case 1:
            unregister_chrdev(major_number, CHARDEV_NAME);
    }
    return -1;
}

extern int init_sysfs(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Initializing sysfs device...\n");
#endif
    //create char device
    major_number = register_chrdev(0, CHARDEV_NAME, &fops);
    if (major_number < 0)
        return major_number;
#ifdef DEBUG
    printk(KERN_DEBUG "Registered chardev %u\n", major_number);
#endif

    //create sysfs class
    sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(sysfs_class)) {
        return cleanup_sysfs(1);
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created class %s\n", sysfs_class->name);
#endif

    //set the default dev attrs so we don't have to manually add and clean them up
    sysfs_class->dev_attrs = stats_attributes;

    //create sysfs device
    sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, CHARDEV_NAME);
    if (IS_ERR(sysfs_device)) {
        return cleanup_sysfs(2);
    }
#ifdef DEBUG
    printk(KERN_DEBUG "created device %s\n", dev_name(sysfs_device));
#endif

    return 0;
}

