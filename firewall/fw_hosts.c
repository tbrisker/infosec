#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

static int major_number;
static struct device *dev = NULL;
static struct file_operations fops = {
    .owner = THIS_MODULE
};

static ssize_t show_hosts(struct device *dev, struct device_attribute *attr, char *buf){
    return 0;
}

static ssize_t set_hosts(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    return 0;
}

/* Array of device attributes to set for the device. */
static struct device_attribute stats_attrs[]= {
    __ATTR(hosts, S_IRUSR | S_IWUSR, show_hosts, set_hosts),
    __ATTR_NULL // stopping condition for loop in device_add_attributes()
};
