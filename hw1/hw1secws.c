#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops forward;
static struct nf_hook_ops incoming;
static struct nf_hook_ops outgoing;

/* utility macros for allowing or denying with logging */
#define ALLOW ({\
            printk(KERN_INFO "*** packet passed ***");\
            return NF_ACCEPT;\
        })

#define DENY ({\
            printk(KERN_INFO "*** packet blocked ***");\
            return NF_DROP;\
        })

/* the main firewall logic lies here */
static unsigned int firewall(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *)){
    if (NF_INET_FORWARD == hooknum)
        DENY;
    else if (NF_INET_LOCAL_OUT == hooknum || NF_INET_LOCAL_IN == hooknum)
        ALLOW;
    return NF_ACCEPT; /* quietly accept at other points */
}

/* This function initializes the hook_ops struct, sets the hooknum and hooks it to the firewall */
static void hook_ops_default(struct nf_hook_ops *hook_ops, unsigned int hooknum){
    memset(hook_ops, 0, sizeof(struct nf_hook_ops));
    hook_ops->pf = PF_INET;
    hook_ops->hooknum = hooknum;
    hook_ops->priority = NF_IP_PRI_FIRST;
    hook_ops->hook = &firewall;
    printk(KERN_INFO "hook %d initialized\n", hooknum);
}

static int __init hw1_init_function(void) {
    int ret;
    printk(KERN_INFO "Initializing hooks...\n");

    hook_ops_default(&forward, NF_INET_FORWARD);
    hook_ops_default(&incoming, NF_INET_LOCAL_IN);
    hook_ops_default(&outgoing, NF_INET_LOCAL_OUT);

    printk(KERN_INFO "Registering hooks...\n");

    if ((ret = nf_register_hook(&forward)) != 0) {
        printk(KERN_ERR "Error registring hook forward, aborting: %d.\n", ret);
        return ret;
    }

    if ((ret = nf_register_hook(&incoming)) != 0) {
        nf_unregister_hook(&forward);
        printk(KERN_ERR "Error registring hook incoming, aborting: %d.\n", ret);
        return ret;
    }

    if ((ret = nf_register_hook(&outgoing)) != 0) {
        nf_unregister_hook(&forward);
        nf_unregister_hook(&incoming);
        printk(KERN_ERR "Error registring hook outgoing, aborting: %d.\n", ret);
        return ret;
    }
    return 0;
}

static void __exit hw1_exit_function(void) {
    printk(KERN_INFO "Removing hooks...\n");
    nf_unregister_hook(&forward);
    nf_unregister_hook(&incoming);
    nf_unregister_hook(&outgoing);
}

module_init(hw1_init_function);
module_exit(hw1_exit_function);

MODULE_LICENSE("GPL");

#undef ALLOW
#undef DENY
