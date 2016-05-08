#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/**********
 * filter *
 **********/

static void parse_ip_hdr(rule_t *pkt, struct sk_buff *skb){
    struct iphdr *ip_header = ip_hdr(skb);
    pkt->src_ip = ip_header->saddr;
    pkt->dst_ip = ip_header->daddr;
    pkt->protocol = ip_header->protocol;
}

static reason_t parse_tcp_hdr(rule_t *pkt, struct sk_buff *skb, char offset){
    struct tcphdr * tcp_header = (struct tcphdr *)(skb_transport_header(skb)+offset);;
    pkt->src_port = tcp_header->source;
    pkt->dst_port = tcp_header->dest;
    pkt->ack = tcp_header -> ack ? ACK_YES : ACK_NO;
    if (tcp_header->fin && tcp_header->urg && tcp_header->psh){ // xmas packet
        pkt->action = NF_DROP;
        return REASON_XMAS_PACKET;
    }
    return 0;
}

static void parse_udp_hdr(rule_t *pkt, struct sk_buff *skb, char offset){
    struct udphdr * udp_header = (struct udphdr *)(skb_transport_header(skb)+offset);
    pkt->src_port = udp_header->source;
    pkt->dst_port = udp_header->dest;
}

static direction_t parse_direction(const struct net_device *in, const struct net_device *out){
    if ((in && !strcmp(in->name, OUT_NET_DEVICE_NAME)) ||
        (out && !strcmp(out->name, IN_NET_DEVICE_NAME)))
        return DIRECTION_IN;
    if ((in && !strcmp(in->name, IN_NET_DEVICE_NAME)) ||
        (out && !strcmp(out->name, OUT_NET_DEVICE_NAME)))
        return DIRECTION_OUT;
    return DIRECTION_ANY;
}

/* the main filter logic - this function decide what packets are blocked and which are allowed */
static unsigned int filter(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *)){
    rule_t pkt = {//we parse the packet into a rule which we compare to the rules table
        .action = DEFAULT_ACTION, //default: accept
        .src_port = PORT_ANY, //set this for protocols w/o ports
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
    pkt.direction = parse_direction(in, out);
    parse_ip_hdr(&pkt, skb);
#ifdef DEBUG
    printk(KERN_DEBUG "ip packet, src: %d, dst: %d, protocol:%d\n", pkt.src_ip, pkt.dst_ip, pkt.protocol);
#endif
    if (hooknum == NF_INET_PRE_ROUTING) // we need to offset the transport header
        offset = 20;

    switch (pkt.protocol){
    case PROT_ICMP:
        break;
    case PROT_TCP:
        reason = parse_tcp_hdr(&pkt, skb, offset); //check for xmas while parsing
        break;
    case PROT_UDP:
        parse_udp_hdr(&pkt, skb, offset);
        break;
    default:
        pkt.protocol = PROT_OTHER; //map any unknown protocols to other
    }

    if (!fw_active){ //don't stop anything if inactive, just log
        reason = REASON_FW_INACTIVE;
        pkt.action = NF_ACCEPT;
    }
    //make decision
    reason = reason ? reason : check_packet(&pkt); //only check if we didn't block yet
    log_row(pkt.protocol, pkt.action, hooknum, pkt.src_ip, pkt.dst_ip,
            pkt.src_port, pkt.dst_port, reason);
    if (pkt.action == NF_ACCEPT)
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

