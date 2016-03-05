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
#ifdef DEBUG
    printk(KERN_INFO "firewall triggered, hooknum: %d, in: %s, out: %s\n",
            hooknum, in ? in->name : "none", out ? out->name : "none");
#endif
    switch (hooknum){
        case NF_INET_FORWARD: /* Deny all forwarded packets */
            printk(KERN_INFO "*** packet blocked ***\n");
            return NF_DROP;
        case NF_INET_LOCAL_OUT: /* Allow packets to or from our host */
        case NF_INET_LOCAL_IN:
            printk(KERN_INFO "*** packet passed ***\n"); /* and fall through to accept */
        default: /* Other hook points will accept without logging - just in case someone hooks into them */
            return NF_ACCEPT;
    }
}

/* This function initializes the hook_ops struct, sets the hooknum and hooks it to the firewall */
static void hook_ops_default(struct nf_hook_ops *hook_ops, unsigned int hooknum){
    memset(hook_ops, 0, sizeof(struct nf_hook_ops));
    hook_ops->pf = PF_INET;
    hook_ops->hooknum = hooknum;
    hook_ops->priority = NF_IP_PRI_FIRST;
    hook_ops->hook = &firewall;
#ifdef DEBUG
    printk(KERN_INFO "hook %d initialized\n", hooknum);
#endif
}

static int __init hw1_init_function(void) {
#ifdef DEBUG
    printk(KERN_INFO "Initializing hooks...\n");
#endif
    /* initialize the hook option structs for the hook points defined by the exercise */
    hook_ops_default(&hooks[0], NF_INET_FORWARD);
    hook_ops_default(&hooks[1], NF_INET_LOCAL_IN);
    hook_ops_default(&hooks[2], NF_INET_LOCAL_OUT);

#ifdef DEBUG
    printk(KERN_INFO "Registering hooks...\n");
#endif
    /* nf_register_hooks will register all the hooks and automatically unregister all of them if one fails */
    return nf_register_hooks(hooks, NUM_HOOKS);
}

static void __exit hw1_exit_function(void) {
#ifdef DEBUG
    printk(KERN_INFO "Removing hooks...\n");
#endif
    nf_unregister_hooks(hooks, NUM_HOOKS);
}

module_init(hw1_init_function);
module_exit(hw1_exit_function);

MODULE_LICENSE("GPL");
