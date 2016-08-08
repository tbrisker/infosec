#ifndef FW_CONN_TAB_H
#define FW_CONN_TAB_H

#define DEVICE_NAME_CONN_TAB        "conn_tab"

/* Possible TCP states + a special state for FTP data connections */
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

#define CON_BUF_SIZE 256 //use 256 bytes to provide a decent buffer but not too long

/* struct representing a connection.
 * Note - this represents both directions as any connection is uniquely identified
 * by the tuple of ips and ports.
 * src represents the initiator (usually the client)
 * dst represents the responder (usually the server)
 */
typedef struct {
    __be32 src_ip;
    __be16 src_port;
    __be32 dst_ip;
    __be16 dst_port;
    char src_state; // the state we assume the client is in
    char dst_state; // the state we assume the server is in
    unsigned long timestamp; //last packet seen - for timeout calculations
    unsigned int hooknum; // make sure we only capture in one hook - for fwd packets
    char buffer[CON_BUF_SIZE]; //buffer for reading the connection data,
    struct list_head list;
} connection;

//CONNECTION_SIZE is defined to only include fields that are sent to the userspace.
#define CONNECTION_SIZE (sizeof(connection)-sizeof(long)-sizeof(int)-sizeof(char)*CON_BUF_SIZE-sizeof(struct list_head))
/* The time to remove a connection if handshake has not been completed or ftp data
 * transfer has been inactive.
 * 10 times this is used to indicate a stale connection that should be closed.
 */
#define TIMEOUT 25

/* Connection table public interface */

/* check if a packet matches an exisiting connection in the table */
reason_t check_conn_tab(rule_t *pkt, struct tcphdr *tcp_header, unsigned int hooknum, unsigned char *tail);
/* add a new connection */
void new_connection(rule_t pkt, unsigned int hooknum);

/*module init*/
int init_conn_tab(void);
/*module cleanup*/
void cleanup_conn_tab(void);

#endif
