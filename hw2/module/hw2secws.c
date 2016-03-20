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

static int init_firewall(){
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

static void cleanup_firewall(){
#ifdef DEBUG
    printk(KERN_DEBUG "Removing hooks...\n");
#endif
    nf_unregister_hooks(hooks, NUM_HOOKS);
}

/***********/
/*  Sysfs  */
/***********/

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static unsigned int sysfs_int = 0;

static struct file_operations fops = {
    .owner = THIS_MODULE
};

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)   //sysfs show implementation
{
    return scnprintf(buf, PAGE_SIZE, "%u\n", sysfs_int);
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)    //sysfs store implementation
{
    int temp;
    if (sscanf(buf, "%u", &temp) == 1)
        sysfs_int = temp;
    return count;
}

static DEVICE_ATTR(sysfs_att, S_IRWXO , display, modify);

static int init_sysfs(void)
{
    //create char device
    major_number = register_chrdev(0, "Sysfs_Device", &fops);\
    if (major_number < 0)
        return -1;

    //create sysfs class
    sysfs_class = class_create(THIS_MODULE, "Sysfs_class");
    if (IS_ERR(sysfs_class))
    {
        unregister_chrdev(major_number, "Sysfs_Device");
        return -1;
    }

    //create sysfs device
    sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "sysfs_class" "_" "sysfs_Device");
    if (IS_ERR(sysfs_device))
    {
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "Sysfs_Device");
        return -1;
    }

    //create sysfs file attributes
    if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
    {
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "Sysfs_Device");
        return -1;
    }

    return 0;
}

static void cleanup_sysfs(void)
{
    device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
    device_destroy(sysfs_class, MKDEV(major_number, 0));
    class_destroy(sysfs_class);
    unregister_chrdev(major_number, "Sysfs_Device");
}

/**********/
/*  CORE  */
/**********/
static int __init hw2_init_function(void) {
    int err = init_firewall();
    if (err)
        return err;
    err = init_sysfs();
    if (err){
        cleanup_firewall();
        return err;
    }
    return 0;
}

static void __exit hw2_exit_function(void) {
    cleanup_sysfs();
    cleanup_firewall();
}

module_init(hw2_init_function);
module_exit(hw2_exit_function);
