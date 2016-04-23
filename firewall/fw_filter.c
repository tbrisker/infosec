#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/**********
 * filter *
 **********/

/* the main filter logic - this function decide what packets are blocked and which are allowed */
static unsigned int filter(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *)){
#ifdef DEBUG
    printk(KERN_DEBUG "filter triggered, hooknum: %d, in: %s, out: %s\n",
            hooknum, in ? in->name : "none", out ? out->name : "none");
#endif
    ++p_total;
    struct sk_buff *packet = skb;
    rule_t rule;
    if (hooknum == NF_INET_PRE_ROUTING){ //incoming
        packet += 20; //skip the network header
        rule.direction = DIRECTION_IN;
    } else { //outgoing
        rule.direction = DIRECTION_OUT;

    }
    PASS_AND_RET;
}

/* Array to hold our hook definitions so we can easily register and unregister them */
static struct nf_hook_ops hooks[NUM_HOOKS] = {
    HOOK_INIT(NF_INET_PRE_ROUTING),
    HOOK_INIT(NF_INET_POST_ROUTING)
};

int init_filter(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Registering hooks...\n");
#endif
    /* nf_register_hooks will register all the hooks and automatically unregister all of them if one fails */
    return nf_register_hooks(hooks, NUM_HOOKS);
}

void cleanup_filter(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Removing hooks...\n");
#endif
    nf_unregister_hooks(hooks, NUM_HOOKS);
}

