#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/**********
 * filter *
 **********/

static void parse_ip_hdr(rule_t *rule, struct sk_buff *skb){
    struct iphdr *ip_header = ip_hdr(skb);
    rule->src_ip = ip_header->saddr;
    rule->dst_ip = ip_header->daddr;
    rule->protocol = ip_header->protocol;
}

static void parse_tcp_hdr(rule_t *rule, struct sk_buff *skb, char offset){
    struct tcphdr * trans_header = (struct tcphdr *)(skb_transport_header(skb)+offset);;
    rule->src_port = trans_header->source;
    rule->dst_port = trans_header->dest;
    rule->ack = trans_header -> ack ? ACK_YES : ACK_NO;
    //check for xmas?
}

static void parse_udp_hdr(rule_t *rule, struct sk_buff *skb, char offset){
    struct udphdr * trans_header = (struct udphdr *)(skb_transport_header(skb)+offset);
    rule->src_port = trans_header->source;
    rule->dst_port = trans_header->dest;
}

/* the main filter logic - this function decide what packets are blocked and which are allowed */
static unsigned int filter(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *)){
    rule_t rule = {//we parse the packet into a rule which we compare to the rules table
        .action = NF_ACCEPT,
        .src_port = PORT_ANY,
        .dst_port = PORT_ANY
    };
    char offset = 0;
    reason_t reason = 0;
#ifdef DEBUG
    printk(KERN_DEBUG "filter triggered, hooknum: %d, in: %s, out: %s, protocol:%d\n",
            hooknum, in ? in->name : "none",
            out ? out->name : "none",
            skb->protocol);
#endif
    ++p_total;
    if (ntohs(skb->protocol) != ETH_P_IP){ //make sure we only handle ipv4 packets
        return NF_ACCEPT;
    }

    parse_ip_hdr(&rule, skb);
#ifdef DEBUG
    printk(KERN_DEBUG "ip packet, src: %d, dst: %d, protocol:%d\n", rule.src_ip, rule.dst_ip, rule.protocol);
#endif
    if (hooknum == NF_INET_PRE_ROUTING){ //incoming
        rule.direction = DIRECTION_IN;
        offset = 20;
    } else { //outgoing
        rule.direction = DIRECTION_OUT;
    }

    switch (rule.protocol){
    case PROT_ICMP:
        break;
    case PROT_TCP:
        parse_tcp_hdr(&rule, skb, offset);
        break;
    case PROT_UDP:
        parse_udp_hdr(&rule, skb, offset);
        break;
    default:
        rule.protocol = PROT_OTHER;
    }

    //make decision
    log_row(rule.protocol, rule.action, hooknum, rule.src_ip, rule.dst_ip,
            rule.src_port, rule.dst_port, reason);
    if (rule.action == NF_ACCEPT)
        PASS_AND_RET;
    DROP_AND_RET;
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

