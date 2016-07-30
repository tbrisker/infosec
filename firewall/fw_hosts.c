#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/************************
 * Blocked hosts module *
 ************************/

/* Internal list representation and helper functions */
/*****************************************************/

static char * host_list; //the blocked host list provided by the user. we just copy it from the user.
static int host_len; // the length of the list

/* check if a given host is on the blocked hosts list */
int check_hosts(char *host){
    char *tmp;
    int len = 0;
    if (host_list == NULL || host == NULL){
        return 0;
    }
    tmp = strstr(host_list, host);
    len = strlen(host);
    while (tmp){
        //make sure we have a complete match
        if ((tmp==host_list || tmp[-1] == '\n') &&
            (tmp[len] == '\n' || tmp[len] == '\r' || tmp[len] == '\0')){
#ifdef DEBUG
            printk(KERN_DEBUG "Blocked host: %s\n", host);
#endif
            return 1;
        }
        tmp = strstr(tmp+1, host);
    }
    return 0;
}

/* hosts list sysfs device functions and handlers */
/**************************************************/

static int major_number;
static struct device *dev = NULL;
static struct file_operations fops = {
    .owner = THIS_MODULE
};

/* show the blocked host list to the user */
static ssize_t show_hosts(struct device *dev, struct device_attribute *attr, char *buf){
#ifdef DEBUG
    printk(KERN_DEBUG "showing hosts, length %d\n", host_len);
#endif
    if (host_list == NULL)
        return 0;
    return scnprintf(buf, host_len+1, "%s\n", host_list);
}

/* load a blocked host list from the user */
static ssize_t set_hosts(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    host_len = count;
#ifdef DEBUG
    printk(KERN_DEBUG "setting hosts, length %d\n", count);
#endif
    if (host_list != NULL)
        kfree(host_list);
    host_list = kmalloc(host_len, GFP_KERNEL);
    if (host_list == NULL){
        printk(KERN_ERR "kmalloc for host list failed\n");
        host_len = 0;
        return -ENOMEM;
    }
    if (scnprintf(host_list, host_len, "%s", buf)<0){
        printk(KERN_ERR "Error copying string from userspace");
        kfree(host_list);
        host_len = 0;
        return -EFAULT;
    }
    return count;
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
    host_list = NULL;
    host_len = 0;
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
    if (host_list != NULL)
        kfree(host_list);
}
