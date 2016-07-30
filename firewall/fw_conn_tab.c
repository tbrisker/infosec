#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/***************************
 * Connection table module *
 ***************************/

/* Internal table representation and helper functions */
/******************************************************/

static LIST_HEAD(conn_table); // init the list representing the connection table

/* removes a connection from the connection table and frees its memory */
static void del_con(connection * con){
    list_del(&con->list);
    kfree(con);
}

/* locate a connection in the connection table or return NULL if a match does not exist */
static connection * find_connection(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port){
    connection *cur, *tmp;
    unsigned long expiry = get_seconds() - TIMEOUT; //timestamp for expiring timed out connections
    unsigned long stale = get_seconds() - TIMEOUT*10; //timestamp for expiring stale connections
    list_for_each_entry_safe(cur, tmp, &conn_table, list){
        //remove any old connections in the handshake stage, inactive ftp data, or closed connections
        if (((cur->src_state == C_SYN_SENT || cur->src_state == C_FTP_DATA) && cur->timestamp < expiry)
            || cur->src_state == C_CLOSED || cur->dst_state == C_CLOSED || cur->timestamp < stale){
            del_con(cur);
            continue;
        }
        if ((cur->src_ip == src_ip && cur->src_port == src_port &&
             cur->dst_ip == dst_ip && cur->dst_port == dst_port) ||
            (cur->src_ip == dst_ip && cur->src_port == dst_port && //reverse direction = same connection
             cur->dst_ip == src_ip && cur->dst_port == src_port))
            return cur;
    }
    return NULL;
}

/* add an ftp data connection to the connection table, based on what was found in
 * and existing ftp connection. If the PORT command contains invalid parameters
 * or an IP different then the client's - block it (by not adding it to the table).
 * PORT is always sent by the client, which is ftp->src, and the server will always
 * be ftp->dst.
 */
static __u8 ftp_handler(connection *ftp){
    __be32 src_ip   = 0;
    __be16 src_port = 0;
    unsigned char tmp[6]; //will be used to parse the ip and port
    connection *con;

    if (sscanf(ftp->buffer, "PORT %hhu,%hhu,%hhu,%hhu,%hhu,%hhu",
               &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) != 6){
        printk(KERN_NOTICE "Bad PORT string: %s\n", ftp->buffer);
        ftp->buffer[0] = '\0';
        return NF_DROP;
    }
    ftp->buffer[0] = '\0';

    //some bit magic to get those numbers into the correct vars
    src_ip = (tmp[3] << 24) | (tmp[2]<<16) | (tmp[1]<<8) | tmp[0]; //net order is big-endian
    src_port = (tmp[5] << 8) | tmp[4];

#ifdef DEBUG
    printk(KERN_DEBUG "Parsed ftp PORT: ip %pI4 port %u\n", &src_ip, ntohs(src_port));
#endif
    //make sure the client didn't spoof a different ip to gain an exception to the fw
    if (src_ip != ftp->src_ip){
        printk(KERN_NOTICE "Non matching ip in port command: client is %pI4 but passed %pI4\n",
            &ftp->src_ip, &src_ip);
        return NF_DROP;
    }

    con = find_connection(src_ip, src_port, ftp->dst_ip, htons(20));
    if (con) // don't add duplicates
        return NF_ACCEPT;
#ifdef DEBUG
    printk(KERN_DEBUG "New ftp data connection: src %pI4:%u dst %pI4:20\n", &src_ip, ntohs(src_port), &ftp->dst_ip);
#endif
    con = kmalloc(sizeof(connection), GFP_ATOMIC);
    if (!con){
        printk(KERN_ERR "Error allocating memory for connection.\n");
        return NF_DROP; //so sender will try again
    }
    con->timestamp = get_seconds();
    con->src_ip    = src_ip;
    con->src_port  = src_port;
    con->dst_ip    = ftp->dst_ip;
    con->dst_port  = htons(20);
    con->src_state = con->dst_state = C_FTP_DATA;
    con->buffer[0] = '\0'; // not really needed here
    list_add(&con->list, &conn_table);
    return NF_ACCEPT;
}

/* handle connection sending a "Host:"" command.
 * check if that host is forbidden and block the packet.
 */
static __u8 host_handler(connection * con){
    con->buffer[0] = '\0'; //reset the buffer for the next lines
    if (check_hosts(&con->buffer[6])){
        return NF_DROP;
    }
    return NF_ACCEPT;
}

/* This is a generic parser that looks for a given string in a line and calls a
 * function if found, and returns its return value.
 */
static __u8 str_parse(connection * con, struct tcphdr *tcp_header, unsigned char *tail,
                        const char * str, __u8 (*handler)(connection *)){
    unsigned char *start = (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
    int i = 0, j = 0;
    int datalen = tail-start; //calculate tcp data length
    int targetlen = strlen(str);
#ifdef DEBUG
    printk(KERN_DEBUG "parsing tcp packet, length %d:\n", datalen);
#endif
    j = strlen(con->buffer); //check if we already started to capture a line in a previous fragment
    for (i=0; i < datalen; i++){
        if (j>targetlen || !strncmp(&start[i], &str[j], min(datalen-i,targetlen-j))){
            while (i < datalen && start[i] != '\r' && start[i] != '\0' && j < CON_BUF_SIZE-1){
                con->buffer[j++] = start[i++];//copy the matching line to the buffer
            }
            con->buffer[j] = '\0';
            if (start[i] == '\r'){//read an entire line
#ifdef DEBUG
                printk(KERN_DEBUG "Found match: %s\n", con->buffer);
#endif
                return handler(con);
            }
            break;
        } else if (j>0) { //false start, reset
            con->buffer[0] = '\0';
            j = 0;
        }
    }
    return NF_ACCEPT;
}

/* check if a given connection is permitted in the connection table
 * and update the connection state if it changed.
 * Set the action on the packet according to the decision and return the reason.
 * Note: this function assumes that tcp_header->ack is true.
 */
reason_t check_conn_tab(rule_t *pkt, struct tcphdr *tcp_header, unsigned int hooknum, unsigned char *tail){
    int reverse; //is this packet in the direction of the initial packet or the reverse?
    connection *con = find_connection(pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port);
    if (NULL == con){ //non existing connection - drop the packet
        pkt->action = NF_DROP;
        return REASON_CONN_NOT_EXIST;
    }
    pkt->action = NF_ACCEPT; //existing connection - default to accept

    if (con->src_state != C_FTP_DATA && con->hooknum != hooknum) //don't check the same packet twice
        return REASON_CONN_EXIST;
    con->timestamp = get_seconds(); //update the timestamp
    reverse = (pkt->src_ip == con->dst_ip && pkt->src_port == con->dst_port &&
               pkt->dst_ip == con->src_ip && pkt->dst_port == con->src_port);

    //in handshake
    if (con->src_state == C_SYN_SENT){
        //handshake stage 2
        if (reverse && con->dst_state == C_LISTEN && tcp_header->syn){
            con->dst_state = C_SYN_RECEIVED;
            return REASON_CONN_EXIST;
        }
        //handshake stage 3
        if (!reverse && con->dst_state == C_SYN_RECEIVED && !tcp_header->syn){
            con->src_state = con->dst_state = C_ESTABLISHED;
            return REASON_CONN_EXIST;
        }
    }
    if (con->src_state != C_FTP_DATA && tcp_header->syn){ //syn is valid only during handshake, drop otherwise
        pkt->action = NF_DROP;
#ifdef DEBUG
        printk(KERN_DEBUG "Dropped packet, unexpected syn\n");
#endif
        return REASON_TCP_NON_COMPLIANT;
    }

    // in established connection
    if (con->src_state == C_ESTABLISHED || con->src_state == C_FTP_DATA) {
        if (tcp_header->fin){ //handle close requests
            if (reverse){ //the server requested the close
                con->src_state = C_CLOSE_WAIT;
                con->dst_state = C_FIN_WAIT_1;
            } else { //the client requested the close
                con->src_state = C_FIN_WAIT_1;
                con->dst_state = C_CLOSE_WAIT;
            }
        } else if (pkt->dst_port == htons(80)){ //scan http connections for blocked hosts
            pkt->action = str_parse(con, tcp_header, tail, "Host: ", host_handler);
            if (pkt->action == NF_DROP){ //close the connection for bad hosts
                con->src_state = con->dst_state = C_CLOSED;
                return REASON_BLOCKED_HOST;
            }
        } else if (pkt->dst_port == htons(21)){ //scan ftp connections for PORT commands
           pkt->action = str_parse(con, tcp_header, tail, "PORT ", ftp_handler);
        }

        //any packet is valid now (we already made sure syn=0, ack=1)
        return REASON_CONN_EXIST;
    }

    //in closing handshake
    if (reverse){
        if (con->src_state == C_FIN_WAIT_1){
            if (tcp_header->fin){
                con->src_state = C_TIME_WAIT;
                con->dst_state = C_LAST_ACK;
            } else {
                con->src_state = C_FIN_WAIT_2;
            }
        } else if (con->src_state == C_FIN_WAIT_2) {
            if (tcp_header->fin){
                con->src_state = C_TIME_WAIT;
                con->dst_state = C_LAST_ACK;
            }
        } else if (con->src_state == C_LAST_ACK) {
            con->src_state = C_CLOSED;
        }
    } else {
        if (con->dst_state == C_FIN_WAIT_1){
            if (tcp_header->fin){
                con->dst_state = C_TIME_WAIT;
                con->src_state = C_LAST_ACK;
            } else {
                con->dst_state = C_FIN_WAIT_2;
            }
        } else if (con->dst_state == C_FIN_WAIT_2) {
            if (tcp_header->fin){
                con->dst_state = C_TIME_WAIT;
                con->src_state = C_LAST_ACK;
            }
        } else if (con->dst_state == C_LAST_ACK) {
            con->dst_state = C_CLOSED;
        }
    }

    return REASON_CONN_EXIST;
}

/* Add a new connection to the connection table */
void new_connection(rule_t pkt, unsigned int hooknum){
    connection *con = find_connection(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port);
    if (con) // don't add duplicates
        return;
#ifdef DEBUG
    printk(KERN_DEBUG "New Conn: src %pI4:%u dst %pI4:%u\n", &pkt.src_ip, ntohs(pkt.src_port), &pkt.dst_ip, ntohs(pkt.dst_port));
#endif
    con = kmalloc(sizeof(connection), GFP_ATOMIC);
    if (!con){
        printk(KERN_ERR "Error allocating memory for connection.\n");
        return;
    }
    con->timestamp = get_seconds();
    con->src_ip    = pkt.src_ip;
    con->src_port  = pkt.src_port;
    con->dst_ip    = pkt.dst_ip;
    con->dst_port  = pkt.dst_port;
    con->src_state = C_SYN_SENT; //handshake stage 1
    con->dst_state = C_LISTEN; //assume the server is listening - will timeout if not
    con->hooknum   = hooknum; //only capture a connection in one hook
    con->buffer[0] = '\0';
    list_add(&con->list, &conn_table);
}

/* clear the connection table and free it's memory*/
static void clear_cons(void){
    connection *cur, *tmp;
    list_for_each_entry_safe(cur, tmp, &conn_table, list){
        del_con(cur);
    }
}

/* connection table char device functions and handlers */
/*******************************************************/

static int major_number;
static struct device *dev = NULL;
static struct list_head *cur_con; // used for iterating the table during read

/* open the connection table char device */
static int open_cons(struct inode *_inode, struct file *_file){
#ifdef DEBUG
    printk(KERN_DEBUG "opened conn_tab\n");
#endif
    cur_con = conn_table.next; //reset the pointer to the first row
    return 0;
}

/* reads the connection table, one connection at a time */
static ssize_t read_cons(struct file *filp, char *buff, size_t length, loff_t *offp){
    unsigned long expiry = get_seconds() - TIMEOUT*10; //expire very stale connections when listing
    connection *tmp;
#ifdef DEBUG
    printk(KERN_DEBUG "read cons, length: %d, row size: %d\n", length, CONNECTION_SIZE);
#endif
    while (cur_con != &conn_table && list_entry(cur_con, connection, list)->timestamp < expiry){
        tmp = list_entry(cur_con, connection, list);
        cur_con = cur_con->next;
        del_con(tmp);
    }
    if (cur_con == &conn_table){ //the table is empty or we reached the end
        return 0;
    }
    if (length < CONNECTION_SIZE){ // length must be at least CONNECTION_SIZE for read to work, we don't send partial rows.
        return -ENOMEM;
    }

    if (copy_to_user(buff, list_entry(cur_con, connection, list), CONNECTION_SIZE)){  // Send the data to the user through 'copy_to_user'
        return -EFAULT;
    }
    cur_con = cur_con->next; //advance to the next connection for the next read
    return CONNECTION_SIZE;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = open_cons,
    .read = read_cons
};

/* initialize the conn_tab module */
int init_conn_tab(void){
#ifdef DEBUG
    printk(KERN_DEBUG "initializing conn_tab device\n");
#endif
    major_number = safe_device_init(DEVICE_NAME_CONN_TAB, &fops, dev, NULL);
    // Since we use safe_device_init, in case of failure all cleanup will be
    // handled already, only need to return 0 for non-negative major (=no error)
    return (major_number < 0) ? major_number : 0;
}

/* cleanup the conn_tab module */
void cleanup_conn_tab(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up conn_tab device\n");
#endif
    safe_device_cleanup(major_number, 3, dev, NULL);
    clear_cons();
}
