#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Brisker");

/******************************/
/*  Firewall rules interface  */
/******************************/

char fw_active; // 0 = deactivated, 1 = activated

static rule_t rule_list[MAX_RULES]; //array of rules
static int rule_count; //number of rules in the list

/* returns true if packet_ip is not in the network defined by rule_ip/nps */
static int check_rule_ip(__be32 rule_ip, __be32 packet_ip, __u8 nps){
    return (rule_ip != 0 && nps != 0 && //ip or prefix == 0 -> any
            (ntohl(rule_ip) >> (32 - nps) != ntohl(packet_ip) >> (32 - nps)));
}

/* returns true if packet port does not match the rule port */
static int check_rule_port(__be32 rule_port, __be32 packet_port){
    return ((rule_port != PORT_ANY && rule_port != PORT_ABOVE_1023 && rule_port != packet_port) ||
            (rule_port == PORT_ABOVE_1023 && packet_port < PORT_ABOVE_1023));
}

/* check if a packet represented as a rule matches the given rule */
static int check_rule(rule_t *packet, rule_t rule){
    if (rule.protocol != PROT_ANY && rule.protocol != packet->protocol)
        return 0;
    if (rule.direction != DIRECTION_ANY && rule.direction != packet->direction)
        return 0;

    if (check_rule_ip(rule.src_ip, packet->src_ip, rule.src_prefix_size) ||
        check_rule_ip(rule.dst_ip, packet->dst_ip, rule.dst_prefix_size))
        return 0;

    if ((packet->protocol == PROT_TCP || packet->protocol == PROT_UDP) && //only check ports for protocols that have one
        (check_rule_port(rule.src_port, packet->src_port) ||
         check_rule_port(rule.dst_port, packet->dst_port)))
        return 0;
    //only check ack for TCP
    if (packet->protocol == PROT_TCP && rule.ack != ACK_ANY && rule.ack != packet->ack)
        return 0;
    //we have a match! set the action to the action defined by the rule.
    packet->action = rule.action;
    return 1;
}

/* Compare a packet represented as a rule against the rule list.
 * If a rule is matched return its number, or REASON_NO_MATCHING_RULE otherwise
 */
reason_t check_packet(rule_t *packet){
    int i;

    for (i = 0; i < rule_count; ++i){
        if (check_rule(packet, rule_list[i]))
            return i;
    }
    return REASON_NO_MATCHING_RULE;
}

/* verify that a rule given by the user is valid */
static int invalid_rule(rule_t rule){
    if (rule.direction < DIRECTION_IN || rule.direction > DIRECTION_ANY ||
        rule.src_prefix_size > 32 || rule.src_prefix_size < 0 ||
        rule.dst_prefix_size > 32 || rule.dst_prefix_size < 0 ||
        rule.src_port > PORT_ABOVE_1023 || rule.src_port < PORT_ANY ||
        rule.dst_port > PORT_ABOVE_1023 || rule.dst_port < PORT_ANY ||
        rule.ack < ACK_NO || rule.ack > ACK_ANY )
        return -1;
    if (rule.protocol != PROT_ICMP && rule.protocol != PROT_TCP &&
        rule.protocol != PROT_UDP && rule.protocol != PROT_OTHER &&
        rule.protocol != PROT_ANY)
        return -1;
    if (rule.action != NF_ACCEPT && rule.action != NF_DROP)
        return -1;
    return 0;
}

/* check if a ruleset given by the user is valid */
static int invalid_ruleset(rule_t ruleset[], int size){
    int i;
    for (i = 0; i < size; ++i)
        if (invalid_rule(ruleset[i]))
            return -1;
    return 0;
}

/* rules char device functions and handlers */
/********************************************/
static int major_number;
static struct device *dev = NULL;

/* send the complete rule list to the user */
static ssize_t read_rules(struct file *filp, char *buff, size_t length, loff_t *offp){
#ifdef DEBUG
    printk(KERN_DEBUG "read rules, length: %d, size: %d\n", length, sizeof(rule_list));
#endif
    if (!rule_count){ //the rule list is empty
        return 0;
    }
    if (length < RULE_SIZE*rule_count){ // length must be at least RULE_SIZE for read to work.
        return -ENOMEM;
    }
    if (copy_to_user(buff, rule_list, RULE_SIZE*rule_count)){  // Send the data to the user through 'copy_to_user'
        return -EFAULT;
    }
    return RULE_SIZE*rule_count;
}

/* get a complete rule list from the user */
static ssize_t write_rules(struct file *filp, const char *buff, size_t length, loff_t *offp){
    // a temporary buffer to get the user input.
    // defined as static so it is placed in global memory but only visible in this scope,
    // it is too large for a local variable. (>1024 bytes)
    static rule_t temp[MAX_RULES];

#ifdef DEBUG
    printk(KERN_DEBUG "write rules, length: %d, size: %d\n", length, sizeof(rule_list));
#endif
    if (length > RULE_SIZE*MAX_RULES){ // data is too big
        return -ENOMEM;
    }
    if (length % RULE_SIZE != 0) { //bad size - only copy complete rules
        return -EINVAL;
    }
    if (copy_from_user(temp, buff, length)){  // get the data from userspace
        return -EFAULT;
    }
    if (invalid_ruleset(temp, length / RULE_SIZE)){ //make sure the rules are valid
        return -EINVAL;
    }
    memcpy(rule_list, temp, length); // override the current list
    rule_count = length / RULE_SIZE; // update the size
    return length;
}

// char device operations
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read_rules,
    .write = write_rules
};

/* log sysfs functions and attributes */
/**************************************/

/* sysfs attribute to show the number of rules to the user */
static ssize_t show_size(struct device *dev, struct device_attribute *attr, char *buf){
    return scnprintf(buf, PAGE_SIZE, "%u\n", rule_count);
}

/* sysfs attribute to show the current fw activation state to the user */
static ssize_t show_active(struct device *dev, struct device_attribute *attr, char *buf){
    return scnprintf(buf, PAGE_SIZE, "%u\n", fw_active);
}

/* sysfs to let the user toggle the fw activation state */
static ssize_t set_active(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    char temp;
    if (sscanf(buf, "%1c", &temp) == 1 && (temp == '0' || temp == '1')){
#ifdef DEBUG
        printk(KERN_DEBUG "setting fw active to %c\n", temp);
#endif
        fw_active = temp - '0';
    }
    return count;
}

/* sysfs attribute to clear all the rules */
static ssize_t clear_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    char temp;
    if (sscanf(buf, "%1c", &temp) == 1){
        rule_count = 0; // no need to actually empty the array, just set the count to 0
    }
    return count;
}

/* sysfs attributes */
static struct device_attribute rule_attrs[]= {
        __ATTR(rules_size, S_IRUSR, show_size, NULL),
        __ATTR(active, S_IWUSR|S_IRUSR, show_active, set_active),
        __ATTR(rules_clear, S_IWUSR, NULL, clear_rules),
        __ATTR_NULL // stopping condition for loop in device_add_attributes()
    };


/* initialize the rules module */
int init_rules(void){
#ifdef DEBUG
    printk(KERN_DEBUG "initializing rules device\n");
#endif
    rule_count = 0;
    fw_active = 0; // start as inactive until activated by user
    major_number = safe_device_init(DEVICE_NAME_RULES, &fops, dev, rule_attrs);
    // Since we use safe_device_init, in case of failure all cleanup will be
    // handled already, only need to return 0 for non-negative major (=no error)
    return (major_number < 0) ? major_number : 0;
}

/* cleanup the rules module */
void cleanup_rules(void){
#ifdef DEBUG
    printk(KERN_DEBUG "Cleaning up rules device\n");
#endif
    safe_device_cleanup(major_number, 3, dev, rule_attrs);
}
