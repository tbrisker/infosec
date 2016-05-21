#ifndef FW_LOG_H
#define FW_LOG_H

#define DEVICE_NAME_LOG             "log"

// various reasons to be registered in each log entry
typedef enum {
    REASON_FW_INACTIVE           = -1,
    REASON_NO_MATCHING_RULE      = -2,
    REASON_XMAS_PACKET           = -4,
    REASON_ILLEGAL_VALUE         = -6,
    REASON_CONN_TAB              = -8
} reason_t;

// log row
typedef struct {
    unsigned long    timestamp;      // time of creation/update
    unsigned char    protocol;       // values from: prot_t
    unsigned char    action;         // valid values: NF_ACCEPT, NF_DROP
    unsigned char    hooknum;        // as received from netfilter hook
    __be32           src_ip;         // if you use this struct in userspace, change the type to unsigned int
    __be32           dst_ip;         // if you use this struct in userspace, change the type to unsigned int
    __be16           src_port;       // if you use this struct in userspace, change the type to unsigned short
    __be16           dst_port;       // if you use this struct in userspace, change the type to unsigned short
    reason_t         reason;         // rule#index, or values from: reason_t
    unsigned int     count;          // counts this line's hits
    struct list_head list;           // the log is a linked list of rows
} log_row_t;
//we don't want to pass the list_head part to the user (as it may leak kernel memory addresses), ignore it in the row size
#define ROW_SIZE (sizeof(log_row_t) - sizeof(struct list_head))

/*********************************************
 * Firewall log interface - "public" methods *
 *********************************************/

/* Add a row to the log with the given parameters - or update a similar row */
int log_row(unsigned char protocol, unsigned char action, unsigned char hooknum,
            __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port,
            reason_t reason);
/* log module initialization */
int init_log(void);
/* log module cleanup */
void cleanup_log(void);

#endif
