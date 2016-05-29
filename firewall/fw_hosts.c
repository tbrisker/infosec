#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

char * host_list;

__u8 check_hosts(char *host){
    if (!strcmp(host, "10.0.1.3"))
        return NF_DROP;
    return NF_ACCEPT;
}

static int major_number;
static struct device *dev = NULL;
static struct file_operations fops = {
    .owner = THIS_MODULE
};

static ssize_t show_hosts(struct device *dev, struct device_attribute *attr, char *buf){
#ifdef DEBUG
    printk(KERN_DEBUG "showing hosts, length %d\n", strlen(host_list));
#endif
    if (host_list == NULL)
        return 0;
    return scnprintf(buf, strlen(host_list), "%s\n", host_list);
}

static ssize_t set_hosts(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    int host_len = min((long)count, strlen_user(buf))+1;
#ifdef DEBUG
    printk(KERN_DEBUG "setting hosts, length %d\n", count);
#endif
    if (host_list != NULL)
        kfree(host_list);
    host_list = kmalloc(host_len, GFP_KERNEL);
    if (host_list == NULL){
        printk(KERN_ERR "kmalloc for host list failed\n");
        return -ENOMEM;
    }
    return scnprintf(host_list, host_len, "%s", buf);
}

/* Array of device attributes to set for the device. */
static struct device_attribute hosts_attrs[]= {
    __ATTR(hosts, S_IRUSR | S_IWUSR, show_hosts, set_hosts),
    __ATTR_NULL // stopping condition for loop in device_add_attributes()
};


/* initialize the hosts module */
int init_hosts(void){
#ifdef DEBUG
    printk(KERN_DEBUG "initializing hosts device\n");
#endif
    major_number = safe_device_init(DEVICE_NAME_HOSTS, &fops, dev, hosts_attrs);
    // Since we use safe_device_init, in case of failure all cleanup will be
    // handled already, only need to return 0 for non-negative major (=no error)
    return (major_number < 0) ? major_number : 0;
}

/* cleanup the hosts module */
void cleanup_hosts(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up hosts device\n");
#endif
    safe_device_cleanup(major_number, 3, dev, hosts_attrs);
}
