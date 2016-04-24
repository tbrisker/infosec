#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/******************************/
/*  Firewall rules interface  */
/******************************/

char fw_active;

static rule_t rule_list[MAX_RULES];
static int rule_count;

/* rules char device functions and handlers */
static int major_number;
static struct device *dev = NULL;

static ssize_t read_rules(struct file *filp, char *buff, size_t length, loff_t *offp){
#ifdef DEBUG
    printk(KERN_DEBUG "read rules, length: %d, size: %d\n", length, sizeof(rule_list));
#endif
    if (!rule_count){ //the rule list is empty
        return 0;
    }
    if (length < RULE_SIZE*rule_count){ // length must be at least RULE_SIZE for read to work, we don't send partial rows.
        return -ENOMEM;
    }
    if (copy_to_user(buff, rule_list, RULE_SIZE*rule_count)){  // Send the data to the user through 'copy_to_user'
        return -EFAULT;
    }
    return RULE_SIZE*rule_count;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read_rules
};

/* log sysfs functions and attributes */
static ssize_t show_size(struct device *dev, struct device_attribute *attr, char *buf){
    return scnprintf(buf, PAGE_SIZE, "%u\n", rule_count);
}
static ssize_t show_active(struct device *dev, struct device_attribute *attr, char *buf){
    return scnprintf(buf, PAGE_SIZE, "%u\n", fw_active);
}
static ssize_t set_active(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    char temp;
    if (sscanf(buf, "%1c", &temp) == 1 && (temp == '0' || temp == '1')){
#ifdef DEBUG
        printk(KERN_DEBUG "setting fw active to %c\n", temp);
#endif
        fw_active = temp - '0';
    }
    return count;
}

static struct device_attribute rule_attrs[]= {
        __ATTR(rules_size, S_IRUSR, show_size, NULL),
        __ATTR(active, S_IWUSR|S_IRUSR, show_active, set_active),
        __ATTR_NULL // stopping condition for loop in device_add_attributes()
    };

int init_rules(void){
    rule_count = 0;
#ifdef DEBUG
    printk(KERN_DEBUG "initializing up rules device\n");
#endif
    major_number = safe_device_init(DEVICE_NAME_RULES, &fops, dev, rule_attrs);
    // Since we use safe_device_init, in case of failure all cleanup will be
    // handled already, only need to return 0 for non-negative major (=no error)
    return (major_number < 0) ? major_number : 0;
}

void cleanup_rules(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up rules device\n");
#endif
    safe_device_cleanup(major_number, 3, dev, rule_attrs);
}
