#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops filter_hook;

unsigned int hw1_filter(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *)){
    printk(KERN_INFO "hook triggered from device: %s\n", in->name);
    return NF_ACCEPT;
}

static int __init hw1_init_function(void) {
    printk(KERN_INFO "Initializing hooks...\n");
    memset(&filter_hook, 0, sizeof(struct nf_hook_ops));
    filter_hook.hook = &hw1_filter;
    filter_hook.pf = PF_INET;
    filter_hook.hooknum = NF_INET_PRE_ROUTING;

    printk(KERN_INFO "Registering hooks...\n");
    nf_register_hook(&filter_hook);
    return 0; /* if non-0 return means init_module  failed */
}
static void __exit hw1_exit_function(void) {
    printk(KERN_INFO "Removing hook...\n");
    nf_unregister_hook(&filter_hook);
}
module_init(hw1_init_function);
module_exit(hw1_exit_function);

MODULE_LICENSE("GPL");
