#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/************/
/* Firewall */
/************/
#define NUM_HOOKS 3

/* Array to hold our hook definitions so we can easily register and unregister them */
static struct nf_hook_ops hooks[NUM_HOOKS];

/* Packet counters */
static unsigned int p_total = 0,
                    p_block = 0,
                    p_pass  = 0;

/* the main firewall logic - this function decide what packets are blocked and which are allowed */
static unsigned int firewall(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *)){
#ifdef DEBUG
    printk(KERN_DEBUG "firewall triggered, hooknum: %d, in: %s, out: %s\n",
            hooknum, in ? in->name : "none", out ? out->name : "none");
#endif
    ++p_total;
    switch (hooknum){
        case NF_INET_FORWARD: /* Deny all forwarded packets */
            printk(KERN_INFO "*** packet blocked ***\n");
            ++p_block;
            return NF_DROP;
        case NF_INET_LOCAL_OUT: /* Allow packets to or from our host */
        case NF_INET_LOCAL_IN:
            printk(KERN_INFO "*** packet passed ***\n"); /* and fall through to accept */
            ++p_pass;
        default: /* Other hook points will accept without logging - just in case someone hooks into them */
            return NF_ACCEPT;
    }
}

/* This function initializes the hook_ops struct, sets the hooknum and connects it to the firewall */
static void hook_ops_init(struct nf_hook_ops *hook_ops, unsigned int hooknum){
    memset(hook_ops, 0, sizeof(struct nf_hook_ops));
    hook_ops->pf = PF_INET;
    hook_ops->hooknum = hooknum;
    hook_ops->priority = NF_IP_PRI_FIRST;
    hook_ops->hook = &firewall;
#ifdef DEBUG
    printk(KERN_DEBUG "hook %d initialized\n", hooknum);
#endif
}

static int init_firewall(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Initializing hooks...\n");
#endif
    /* initialize the hook option structs for the hook points defined by the exercise */
    hook_ops_init(&hooks[0], NF_INET_FORWARD);
    hook_ops_init(&hooks[1], NF_INET_LOCAL_IN);
    hook_ops_init(&hooks[2], NF_INET_LOCAL_OUT);

#ifdef DEBUG
    printk(KERN_DEBUG "Registering hooks...\n");
#endif
    /* nf_register_hooks will register all the hooks and automatically unregister all of them if one fails */
    return nf_register_hooks(hooks, NUM_HOOKS);
}

static void cleanup_firewall(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Removing hooks...\n");
#endif
    nf_unregister_hooks(hooks, NUM_HOOKS);
}

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
    switch (attr->attr.name[0]){
        case 't': //total
            return scnprintf(buf, PAGE_SIZE, "%u\n", p_total);
        case 'b': //blocked
            return scnprintf(buf, PAGE_SIZE, "%u\n", p_block);
        case 'p': //passed
            return scnprintf(buf, PAGE_SIZE, "%u\n", p_pass);
    }
    return -1;
}

static ssize_t reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    int temp;
    if (sscanf(buf, "%u", &temp) == 1 && temp == 0){
#ifdef DEBUG
    printk(KERN_DEBUG "Reseting counters.\n");
#endif
        p_total = 0;
        p_block = 0;
        p_pass  = 0;
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

static int cleanup_sysfs(int step){
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

static int init_sysfs(void){
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


/**********/
/*  CORE  */
/**********/
static int __init hw2_init_function(void) {
    int err;
    if ((err = init_firewall())){
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "Firewall initialized successfully!\n");
#endif
    if ((err = init_sysfs())){
        cleanup_firewall();
        return err;
    }
#ifdef DEBUG
    printk(KERN_DEBUG "sysfs interface initialized successfully!\n");
#endif
    return 0;
}

static void __exit hw2_exit_function(void) {
    cleanup_sysfs(3);
    cleanup_firewall();
}

module_init(hw2_init_function);
module_exit(hw2_exit_function);
