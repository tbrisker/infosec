#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

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

static int __init hw1_init_function(void) {
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

static void __exit hw1_exit_function(void) {
#ifdef DEBUG
    printk(KERN_DEBUG "Removing hooks...\n");
#endif
    nf_unregister_hooks(hooks, NUM_HOOKS);
}

module_init(hw1_init_function);
module_exit(hw1_exit_function);
