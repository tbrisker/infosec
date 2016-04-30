#ifndef FW_FILTER_H
#define FW_FILTER_H

#define NUM_HOOKS 2

#define HOOK_INIT(_number) {     \
    .hook     = &filter,         \
    .pf       = PF_INET,         \
    .hooknum  = _number,         \
    .priority = NF_IP_PRI_FIRST, \
    .owner    = THIS_MODULE      \
}

#define DROP_AND_RET { \
    printk(KERN_INFO "*** packet blocked ***\n"); \
    ++p_block; \
    return NF_DROP; \
}

#define PASS_AND_RET { \
    printk(KERN_INFO "*** packet passed ***\n"); \
    ++p_pass; \
    return NF_ACCEPT; \
}

#define LOOPBACK_NET_DEVICE_NAME    "lo"
#define IN_NET_DEVICE_NAME          "eth1"
#define OUT_NET_DEVICE_NAME         "eth2"

/************************************
 * Firewall filter "public" methods *
 ************************************/

/* initialize the filter - reset counters, set up and register hooks.
 * returns 0 on success, negative error otherwise
 */
int init_filter(void);

/* cleanup the filter - unregister hooks */
void cleanup_filter(void);
#endif
