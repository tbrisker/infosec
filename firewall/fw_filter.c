#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/************************
 * Packet filter module *
 ************************/

/* check if the packet is incoming, outgoing or neither */
static direction_t parse_direction(const struct net_device *in, const struct net_device *out){
    //either in or out will be NULL, depending on which hook we are in.
    if ((in && !strcmp(in->name, OUT_NET_DEVICE_NAME)) ||
        (out && !strcmp(out->name, IN_NET_DEVICE_NAME)))
        return DIRECTION_IN;
    if ((in && !strcmp(in->name, IN_NET_DEVICE_NAME)) ||
        (out && !strcmp(out->name, OUT_NET_DEVICE_NAME)))
        return DIRECTION_OUT;
    return DIRECTION_ANY;
}

/* Parse the packet's ip header to get ip addresses and protocol */
static char parse_ip_hdr(rule_t *pkt, struct sk_buff *skb){
    struct iphdr *ip_header = ip_hdr(skb);
    pkt->src_ip = ip_header->saddr;
    pkt->dst_ip = ip_header->daddr;
    pkt->protocol = ip_header->protocol;
    // check if the transport header still points to the network header and we
    // need to set offset. Loosely inspired by
    // http://stackoverflow.com/questions/29656012/netfilter-like-kernel-module-to-get-source-and-destination-address/
    if ((unsigned char*)ip_header == skb_transport_header(skb))
        return ip_header->ihl * 4;
    return 0;
}

/* Parse the packet's tcp header to get ports and check flags */
/* returns REASON_XMAS_PACKET in case the packet matches the xmas pattern */
static reason_t parse_tcp_hdr(rule_t *pkt, struct sk_buff *skb, char offset, unsigned int hooknum){
    struct tcphdr *tcp_header = (struct tcphdr *)(skb_transport_header(skb)+offset);
    pkt->src_port = tcp_header->source;
    pkt->dst_port = tcp_header->dest;
    if (!fw_active) // if firewall is inactive we only need the ports for logging.
        return REASON_FW_INACTIVE;

    pkt->ack = tcp_header->ack ? ACK_YES : ACK_NO;
    // xmas packet - drop it
    if (tcp_header->fin && tcp_header->urg && tcp_header->psh){
        pkt->action = NF_DROP;
        return REASON_XMAS_PACKET;
    }
    if (tcp_header->ack || pkt->src_port == htons(20)){ //established connection or ftp syn
        return check_conn_tab(pkt, tcp_header, hooknum, skb_tail_pointer(skb));
    }
    if (!tcp_header->syn){ //if ack=0, this is the first packet and must have syn=1
        pkt->action = NF_DROP;
        return REASON_TCP_NON_COMPLIANT;
    }
    return 0;
}

/* Parse the packet's udp header to get ports */
static void parse_udp_hdr(rule_t *pkt, struct sk_buff *skb, char offset){
    struct udphdr *udp_header = (struct udphdr *)(skb_transport_header(skb)+offset);
    pkt->src_port = udp_header->source;
    pkt->dst_port = udp_header->dest;
}

/* the main filter logic - this function decide what packets are blocked and which are allowed */
static unsigned int filter(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *)){
    //we parse the packet into a rule which we compare to the rules table
    rule_t pkt = {
        .action = DEFAULT_ACTION, //default action can be determined by this macro
        .src_port = PORT_ANY, //set this for protocols w/o ports
        .dst_port = PORT_ANY
    };
    char offset = 0;
    reason_t reason = 0;
#ifdef DEBUG
    printk(KERN_DEBUG "filter triggered, hooknum: %d, in: %s, out: %s, network protocol:%d\n",
            hooknum, in ? in->name : "none", out ? out->name : "none", skb->protocol);
#endif
    ++p_total;
    if (ntohs(skb->protocol) != ETH_P_IP){ //make sure we only handle ipv4 packets - should always be false
        return NF_ACCEPT;
    }

    pkt.direction = parse_direction(in, out);
    offset = parse_ip_hdr(&pkt, skb);
#ifdef DEBUG
    printk(KERN_DEBUG "ip packet, src: %pI4, dst: %pI4, transport protocol:%d\n", &pkt.src_ip, &pkt.dst_ip, pkt.protocol);
#endif

    // get the ports for the log, and handle more complex tcp checks on the way
    switch (pkt.protocol){
    case PROT_ICMP: //ICMP has no ports
        break;
    case PROT_TCP:
        reason = parse_tcp_hdr(&pkt, skb, offset, hooknum); //check the connection tab when parsing
        break;
    case PROT_UDP:
        parse_udp_hdr(&pkt, skb, offset);
        break;
    default:
        pkt.protocol = PROT_OTHER; //map any unknown protocols to other
    }

    if (!fw_active){ //don't stop anything if inactive, just log - just to make sure.
        reason = REASON_FW_INACTIVE;
        pkt.action = NF_ACCEPT;
    }
    //make the routing decision based on the rules, only check if we didn't set reason yet
    reason = reason ? reason : check_packet(&pkt);
    //log the packet
    log_row(pkt.protocol, pkt.action, hooknum, pkt.src_ip, pkt.dst_ip,
            pkt.src_port, pkt.dst_port, reason);
    //print the decision to the kernel log, update counter and return decision.
    if (pkt.action == NF_ACCEPT){
        if (pkt.protocol == PROT_TCP && pkt.ack == ACK_NO && pkt.src_port != htons(20) && pkt.dst_port != htons(20))
            new_connection(pkt, hooknum); // add a new connection to the connection tab
        PASS_AND_RET;
    }
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

