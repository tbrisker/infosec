#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

static LIST_HEAD(conn_table); // init the list representing the connection table

static void del_con(connection * con){
    list_del(&con->list);
    kfree(con);
}

/* locate a connection in the connection table or return NULL if does not exist */
static connection * find_connection(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port){
    connection *cur, *tmp;
    unsigned long expiry = get_seconds() - TIMEOUT; //timestamp for expiring old connections
    list_for_each_entry_safe(cur, tmp, &conn_table, list){
        if (cur->timestamp < expiry || cur->src_state == C_CLOSED || cur->dst_state == C_CLOSED){
            del_con(cur);
            continue;
        }
        if ((cur->src_ip == src_ip && cur->src_port == src_port &&
             cur->dst_ip == dst_ip && cur->dst_port == dst_port) ||
            (cur->src_ip == dst_ip && cur->src_port == dst_port && //reverse direction - same connection
             cur->dst_ip == src_ip && cur->dst_port == src_port))
            return cur;
    }
    return NULL;
}

/* check if a given connection is permitted in the connection table
 * and update the connection state if it changed.
 * Sets the action on the packet according to the decision.
 * Note: this function assumes that tcp_header->ack is true.
 */
reason_t check_conn_tab(rule_t *pkt, struct tcphdr *tcp_header){
    int reverse; //is this packet in the original direction or reversed?
    connection *con = find_connection(pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port);
    if (NULL == con){ //non existing connection - drop the packet
        pkt->action = NF_DROP;
        return REASON_CONN_NOT_EXIST;
    }
    pkt->action = NF_ACCEPT; //existing connection - default to accept
    reverse = (pkt->src_ip == con->dst_ip && pkt->src_port == con->dst_port);

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
        // any packet that doesn't match the handshake protocol is invalid.
        pkt->action = NF_DROP;
        return REASON_TCP_NON_COMPLIANT;
    }
    if (tcp_header->syn){ //syn is valid only during handshake, drop otherwise
        pkt->action = NF_DROP;
        return REASON_TCP_NON_COMPLIANT;
    }

    // in established connection
    if (con->src_state == C_ESTABLISHED) {
        if (tcp_header->fin){ //handle close requests
            if (reverse){ //the server requested the close
                con->src_state = C_CLOSE_WAIT;
                con->dst_state = C_FIN_WAIT_1;
            } else { //the client requested the close
                con->src_state = C_FIN_WAIT_1;
                con->dst_state = C_CLOSE_WAIT;
            }
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
void new_connection(rule_t pkt){
    connection *con = kmalloc(sizeof(connection), GFP_ATOMIC);
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
    list_add(&con->list, &conn_table);
}

static void clear_cons(void){
    connection *cur, *tmp;
    list_for_each_entry_safe(cur, tmp, &conn_table, list){
        del_con(cur);
    }
}

static int major_number;
static struct device *dev = NULL;
static struct list_head *cur_con; // used for iterating the list during read

static int open_cons(struct inode *_inode, struct file *_file){
#ifdef DEBUG
    printk(KERN_DEBUG "opened log\n");
#endif
    cur_con = conn_table.next; //reset the pointer to the first row
    return 0;
}

static ssize_t read_cons(struct file *filp, char *buff, size_t length, loff_t *offp){
#ifdef DEBUG
    printk(KERN_DEBUG "read log, length: %d, log size: %d, row size: %d\n", length, log_size, CONNECTION_SIZE);
#endif
    unsigned long expiry = get_seconds() - TIMEOUT; //timestamp for expiring old connections
    connection *tmp;
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
