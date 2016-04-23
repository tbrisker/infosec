#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");


/* Packet counters */
unsigned int p_total, p_block, p_pass;

static void reset_counters(void){
    p_total = p_block = p_pass = 0;
}

static int get_counter(char id){
    switch (id){
        case 't': //total
            return p_total;
        case 'b': //blocked
            return p_block;
        case 'p': //passed
            return p_pass;
    }
    return -1;
}

/******************************/
/*  Firewall stats interface  */
/******************************/

/* Handler function for displaying a certain attribute.
 * gets the counter from the firewall matching the attribute name first letter.
 */
static ssize_t display(struct device *dev, struct device_attribute *attr, char *buf){
#ifdef DEBUG
    printk(KERN_DEBUG "displaying %s\n", attr->attr.name);
#endif
    return scnprintf(buf, PAGE_SIZE, "%u\n", get_counter(attr->attr.name[0]));
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

/* variables to hold various needed structs and identifiers. */
static int major_number;
static struct device* dev = NULL;
static struct file_operations fops = {
    .owner = THIS_MODULE
};

/* Array of device attributes to set for the device. */
static struct device_attribute stats_attrs[]= {
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
    reset_counters();
    major_number = safe_device_init(DEVICE_NAME_STATS, &fops, dev, stats_attrs);
    // Since we use safe_device_init, in case of failure all cleanup will be
    // handled already, only need to return 0 for non-negative major (=no error)
    return (major_number < 0) ? major_number : 0;
}

void cleanup_stats(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up stats\n");
#endif
    safe_device_cleanup(major_number, 3, dev, stats_attrs);
}
