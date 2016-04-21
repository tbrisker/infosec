#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");


/* Internal log representation and helper functions */

/* init the list representing the log */
static LIST_HEAD(log_list);
static int log_size;

/* Compare two log rows to see if they can be combined */
static int compare_rows(log_row_t first, log_row_t second){
    return (first.protocol == second.protocol &&
            first.action   == second.action   &&
            first.hooknum  == second.hooknum  &&
            first.src_ip   == second.src_ip   &&
            first.src_port == second.src_port &&
            first.dst_ip   == second.dst_ip   &&
            first.dst_port == second.dst_port &&
            first.reason   == second.reason)
}

/* If a similar row is already in the list, return it, NULL otherwise */
static log_row_t * find_row(log_row_t * row){
    log_row_t * cur;
    list_for_each_entry(cur, &log_list, list){
        if (compare_rows(*cur, *row))
            return cur;
    }
    return NULL;
}

/* Add a log_row_t entry to the log or update an existing similar one */
static void log_row(log_row_t * new_row){
    log_row_t * old_row = find_row(new_row);
    if (old_row){ //A similar row already exists
        old_row->timestamp = new_row.timestamp;
        old_row->count++;
        kfree(new_row); //no need to save the row, free the memory
    } else { //this is the first time we have such a row, add it to the list.
        new_row->count = 1;
        ++log_size;
        list_add(&new_row->list, log_list);
    }
}

/* Add a row to the list with the given parameters. */
/* Note: the row is allocated memory, make sure to delete it when done */
int add_row(unsigned char protocol, unsigned char action, unsigned char hooknum,
            __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port,
            reason_t reason)
    log_row_t * row = kmalloc(sizof(log_row_t), GFP_KERNEL);
    if (!row){
        printk(KERN_ERR "Error allocating memory for log row.\n");
        return -ENOMEM;
    }
    row->protocol  = protocol;
    row->action    = action;
    row->hooknum   = hooknum;
    row->src_ip    = src_ip;
    row->dst_ip    = dst_ip;
    row->src_port  = src_port;
    row->dst_port  = dst_port;
    row->reason    = reason;
    row->timestamp = get_seconds();
    log_row(row);
    return 0;
}

static void clear_log(void){
    log_row_t * cur, * tmp;
    list_for_each_entry_safe(cur, tmp, log_list, list){
        list_del(cur->list);
        kfree(cur);
    }
}

/* log char device functions and handlers */
static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static unsigned int sysfs_int = 0;
static unsigned int sysfs_int_2 = 1;

ssize_t read_log(struct file *filp, char *buff, size_t length, loff_t *offp)
{
    if (!log_size)
        return 0;
    if (copy_to_user(buff, str, str_len))  // Send the data to the user through 'copy_to_user'
        return -EFAULT;
    return strlen(str);
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read_log
};
