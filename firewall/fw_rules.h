#ifndef FW_RULES_H
#define FW_RULES_H

#define DEVICE_NAME_RULES           "rules"

// auxiliary values, for your convenience
#define IP_VERSION      (4)
#define PORT_ANY        (0)
#define PORT_ABOVE_1023 (1023)
#define MAX_RULES       (50)

// the protocols we will work with
typedef enum {
    PROT_ICMP   = 1,
    PROT_TCP    = 6,
    PROT_UDP    = 17,
    PROT_OTHER  = 255,
    PROT_ANY    = 143,
} prot_t;

typedef enum {
    ACK_NO      = 0x01,
    ACK_YES     = 0x02,
    ACK_ANY     = ACK_NO | ACK_YES,
} ack_t;

typedef enum {
    DIRECTION_IN    = 0x01,
    DIRECTION_OUT   = 0x02,
    DIRECTION_ANY   = DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
    char rule_name[20];         // names will be no longer than 19 chars
    direction_t direction;
    __be32  src_ip;
    __u8    src_prefix_size;    // valid values: 0-32, e.g., /24 for the example above
    __be32  dst_ip;
    __u8    dst_prefix_size;    // as above
    __be16  src_port;           // number of port or 0 for any or port 1023 for any port number > 1023
    __be16  dst_port;           // number of port or 0 for any or port 1023 for any port number > 1023
    __u8    protocol;           // values from: prot_t
    ack_t   ack;                // values from: ack_t
    __u8    action;             // valid values: NF_ACCEPT, NF_DROP
} rule_t;

extern char fw_active;

#define RULE_SIZE sizeof(rule_t)
/***********************************************
 * Firewall rules interface - "public" methods *
 ***********************************************/

reason_t check_packet(rule_t *packet);
int init_rules(void);
void cleanup_rules(void);
#endif
