#ifndef FW_CONN_TAB_H
#define FW_CONN_TAB_H

#define DEVICE_NAME_CONN_TAB        "conn_tab"

typedef enum {
    C_CLOSED,
    C_LISTEN,
    C_SYN_SENT,
    C_SYN_RECEIVED,
    C_ESTABLISHED,
    C_CLOSE_WAIT,
    C_LAST_ACK,
    C_FIN_WAIT_1,
    C_FIN_WAIT_2,
    C_CLOSING,
    C_TIME_WAIT,
    C_FTP_DATA
} conn_state;

#define CON_BUF_SIZE 100
typedef struct {
    __be32 src_ip;
    __be16 src_port;
    __be32 dst_ip;
    __be16 dst_port;
    char src_state; //the connection initiator will be src
    char dst_state;
    unsigned long timestamp; //last packet - for timeout calculation
    unsigned int hooknum; // make sure we only capture in one hook - for fwd packets
    char buffer[CON_BUF_SIZE];
    struct list_head list;
} connection;

#define CONNECTION_SIZE (sizeof(connection)-sizeof(long)-sizeof(int)-sizeof(char)*CON_BUF_SIZE-sizeof(struct list_head))
#define TIMEOUT 25

reason_t check_conn_tab(rule_t *pkt, struct tcphdr *tcp_header, unsigned int hooknum, unsigned char *tail);
reason_t check_ftp_data(rule_t *pkt);
void new_connection(rule_t pkt, unsigned int hooknum);

int init_conn_tab(void);
void cleanup_conn_tab(void);

#endif
