#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");


/* Internal log representation and helper functions */

/* init the list representing the log */
static LIST_HEAD(log_list);
static struct list_head *cur_row; //used for iterating the list for read
static unsigned int log_size;

/* Compare two log rows to see if they can be combined */
static int compare_rows(log_row_t first, log_row_t second){
    return (first.protocol == second.protocol &&
            first.action   == second.action   &&
            first.hooknum  == second.hooknum  &&
            first.src_ip   == second.src_ip   &&
            first.src_port == second.src_port &&
            first.dst_ip   == second.dst_ip   &&
            first.dst_port == second.dst_port &&
            first.reason   == second.reason);
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
static void add_row(log_row_t * new_row){
    log_row_t * old_row = find_row(new_row);
    if (old_row){ //A similar row already exists
        old_row->timestamp = new_row->timestamp;
        old_row->count++;
        kfree(new_row); //no need to save the row, free the memory
    } else { //this is the first time we have such a row, add it to the list.
        new_row->count = 1;
        ++log_size;
        list_add_tail(&new_row->list, &log_list);
    }
}

/* Add a row to the list with the given parameters. */
/* Note: the row is allocated memory, make sure to delete it when done */
int log_row(unsigned char protocol, unsigned char action, unsigned char hooknum,
            __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port,
            reason_t reason){
    log_row_t * row = kmalloc(sizeof(log_row_t), GFP_ATOMIC);
    memset(row, 0, sizeof(log_row_t));
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
    add_row(row);
    return 0;
}

static void clear_log(void){
    log_row_t *cur, *tmp;
    cur_row = &log_list; // prevent reads while deleting the list
    list_for_each_entry_safe(cur, tmp, &log_list, list){
        list_del(&cur->list);
        kfree(cur);
    }
    log_size = 0;
}

/* log char device functions and handlers */
static int major_number;
static struct device *dev = NULL;

static int open_log(struct inode *_inode, struct file *_file){
#ifdef DEBUG
    printk(KERN_DEBUG "opened log\n");
#endif
    cur_row = log_list.next;
    return 0;
}

static ssize_t read_log(struct file *filp, char *buff, size_t length, loff_t *offp){
#ifdef DEBUG
    printk(KERN_DEBUG "read log, length: %d, log size: %d, row size: %d\n", length, log_size, ROW_SIZE);
#endif
    if (!log_size || cur_row == &log_list){ //the log is empty or we reached the end
        return 0;
    }
    if (length < ROW_SIZE){ // length must be at least ROWSIZE for read to work, we don't send partial rows.
        return -ENOMEM;
    }
    if (copy_to_user(buff, list_entry(cur_row, log_row_t, list), ROW_SIZE)){  // Send the data to the user through 'copy_to_user'
        return -EFAULT;
    }
    cur_row = cur_row->next; //advance to the next row for the next read
    return ROW_SIZE;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = open_log,
    .read = read_log
};

/* log sysfs functions and attributes */
static ssize_t show_size(struct device *dev, struct device_attribute *attr, char *buf){
    return scnprintf(buf, PAGE_SIZE, "%u\n", log_size);
}

static ssize_t sysfs_clear(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    char temp;
    if (sscanf(buf, "%1c", &temp) == 1){
        clear_log();
    }
    return count;
}

static struct device_attribute log_attrs[]= {
        __ATTR(log_size, S_IRUSR, show_size, NULL),
        __ATTR(log_clear, S_IWUSR, NULL, sysfs_clear),
        __ATTR_NULL // stopping condition for loop in device_add_attributes()
    };

int init_log(void) {
    log_size = 0;
    major_number = safe_device_init(DEVICE_NAME_LOG, &fops, dev, log_attrs);
    // Since we use safe_device_init, in case of failure all cleanup will be
    // handled already, only need to return 0 for non-negative major (=no error)
    return (major_number < 0) ? major_number : 0;
}

void cleanup_log(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up log device\n");
#endif
    safe_device_cleanup(major_number, 3, dev, log_attrs);
}
