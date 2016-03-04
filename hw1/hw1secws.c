#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define NUM_HOOKS 3

static struct nf_hook_ops hooks[NUM_HOOKS];

/* the main firewall logic lies here */
static unsigned int firewall(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *)){
#ifdef HW1_DEBUG
    printk("hooknum: %d, in: %s, out: %s\n", hooknum, in ? in->name : "none", out ? out->name : "none");
#endif
    if (NF_INET_FORWARD == hooknum){
        printk(KERN_INFO "*** packet blocked ***\n");
        return NF_DROP;
    };
    else if (NF_INET_LOCAL_OUT == hooknum || NF_INET_LOCAL_IN == hooknum) {
        printk(KERN_INFO "*** packet passed ***\n");
        return NF_ACCEPT;
    }
    return NF_ACCEPT; /* quietly accept at other points, should they be hooked */
}

/* This function initializes the hook_ops struct, sets the hooknum and hooks it to the firewall */
static void hook_ops_default(struct nf_hook_ops *hook_ops, unsigned int hooknum){
    memset(hook_ops, 0, sizeof(struct nf_hook_ops));
    hook_ops->pf = PF_INET;
    hook_ops->hooknum = hooknum;
    hook_ops->priority = NF_IP_PRI_FIRST;
    hook_ops->hook = &firewall;
#ifdef HW1_DEBUG
    printk(KERN_INFO "hook %d initialized\n", hooknum);
#endif
}

static int __init hw1_init_function(void) {
#ifdef HW1_DEBUG
    printk(KERN_INFO "Initializing hooks...\n");
#endif

    hook_ops_default(&hooks[0], NF_INET_FORWARD);
    hook_ops_default(&hooks[1], NF_INET_LOCAL_IN);
    hook_ops_default(&hooks[2], NF_INET_LOCAL_OUT);

#ifdef HW1_DEBUG
    printk(KERN_INFO "Registering hooks...\n");
#endif
    return nf_register_hooks(hooks, NUM_HOOKS);
}

static void __exit hw1_exit_function(void) {
#ifdef HW1_DEBUG
    printk(KERN_INFO "Removing hooks...\n");
#endif
    nf_unregister_hooks(hooks, 3);
}

module_init(hw1_init_function);
module_exit(hw1_exit_function);

MODULE_LICENSE("GPL");
