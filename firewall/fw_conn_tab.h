#ifndef FW_CONN_TAB_H
#define FW_CONN_TAB_H

#define DEVICE_NAME_CONN_TAB        "conn_tab"

typedef enum {
    CLOSED
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    CLOSE_WAIT,
    LAST_ACK,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSING,
    TIME_WAIT,
} conn_state;

typedef struct {
    __be32 src_ip;
    __be16 src_port;
    __be32 dst_ip;
    __be16 dst_port;
    conn_state state;
    unsigned long timestamp; //last packet - for timeout calculation
    struct list_head list;
} connection;

#define CONNECTION_SIZE (sizeof(connection) - sizeof(struct list_head))

int check_conn_tab(rule_t *pkt, struct tcphdr *tcp_header);
void new_connection(rule_t pkt);

#endif
