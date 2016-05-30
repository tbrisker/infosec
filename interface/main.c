#include "main.h"

/* print a log row in a user-readable manner */
void print_log_row(log_row_t row){
    char src_ip[16], dst_ip[16]; // max ip length: 4*3+3*1=15
    inet_ntop(AF_INET, &row.src_ip, src_ip, 16); //convert the ips to strings
    inet_ntop(AF_INET, &row.dst_ip, dst_ip, 16);
    printf("%s\t%-15s\t%-15s\t%-9hu%-9hu%-9s%-8hhu%-7s%-24s%u\n",
        time_to_s(row.timestamp),
        src_ip,
        dst_ip,
        ntohs(row.src_port),
        ntohs(row.dst_port),
        prot_to_s(row.protocol),
        row.hooknum,
        action_to_s(row.action),
        reason_to_s(row.reason),
        row.count);
}

/* show the fw log */
void show_log(void){
    int fd;
    fd = open(DEV_PATH("log"), O_RDONLY);
    if (fd<0){
        perror("Error opening file");
        return;
    }
    printf("timestamp\t\tsrc_ip\t\tdst_ip\t\tsrc_port dst_port protocol hooknum action reason\t\t  count\n");
    log_row_t row;
    while (read(fd, &row, sizeof(log_row_t)) == sizeof(log_row_t)) { //read the log row by row and print them
        print_log_row(row);
    }
    close(fd);
}

/* print a rule in user-readable format */
void print_rule(rule_t rule){
    printf("%s %s %s %s %s %s %s %s %s\n",
        rule.rule_name,
        dir_to_s(rule.direction),
        ip_and_mask_to_s(rule.src_ip, rule.src_prefix_size),
        ip_and_mask_to_s(rule.dst_ip, rule.dst_prefix_size),
        prot_to_s(rule.protocol),
        port_to_s(rule.src_port),
        port_to_s(rule.dst_port),
        ack_to_s(rule.ack),
        action_to_s(rule.action));
}

/* show all rules from the char device to the user */
void show_rules(){
    int fd, i, count;
    rule_t rules[MAX_RULES];
    fd = open(DEV_PATH("rules"), O_RDONLY);
    if (fd < 0){
        perror("Error opening file");
        return;
    }
    count = read(fd, rules, RULE_SIZE*MAX_RULES); // read up to the maximum size
    close(fd);
    if (count < 0){
        perror("Error reading file");
        return;
    }
    count = count / RULE_SIZE; //only print the rules that were returned
    for (i = 0; i < count; ++i)
        print_rule(rules[i]);
}

/* parse a user provided rule to a rule_t, or return -1 on invalid value */
int parse_rule(char *str, rule_t *rule){
    char *tok;
    int tmp;
    tok = strtok(str, " ");
    if (sscanf(tok, "%19s", rule->rule_name) != 1)
        return -1;

    tok = strtok(NULL, " ");
    rule->direction = s_to_dir(tok);
    if (rule->direction < 0)
        return -1;

    tok = strtok(NULL, " ");
    tmp = s_to_ip_and_mask(tok, &rule->src_ip);
    if (tmp == -1)
        return -1;
    rule->src_prefix_size = tmp;

    tok = strtok(NULL, " ");
    tmp = s_to_ip_and_mask(tok, &rule->dst_ip);
    if (tmp == -1)
        return -1;
    rule->dst_prefix_size = tmp;

    tok = strtok(NULL, " ");
    rule->protocol = s_to_prot(tok);
    if (rule->protocol == -1)
        return -1;

    tok = strtok(NULL, " ");
    rule->src_port = s_to_port(tok);
    if (rule->src_port == -1)
        return -1;

    tok = strtok(NULL, " ");
    rule->dst_port = s_to_port(tok);
    if (rule->dst_port == -1)
        return -1;

    tok = strtok(NULL, " ");
    rule->ack = s_to_ack(tok);
    if (rule->ack == -1)
        return -1;

    tok = strtok(NULL, "\r\n"); //this should be the end of the line - remove any line breaks
    rule->action = s_to_action(tok);
    if (rule->action == -1)
        return -1;

    return 0;
}

/* parse the rule file line by line */
int parse_rules(FILE *fp, rule_t rules[]){
    char buf[FORMATTED_RULE_SIZE];
    int count = 0;

    while (fgets(buf, FORMATTED_RULE_SIZE, fp) && count < MAX_RULES){
        if (parse_rule(buf, &rules[count])){
            printf("Invalid rule: %s\n", buf);
            return -1;
        }
        count++;
    }
    return count;
}

/* write a rule list to the char device */
void write_rules(rule_t rules[], int count){
    int fd;
    fd = open(DEV_PATH("rules"), O_WRONLY);
    if (fd<0){
        perror("Error opening file");
        return;
    }
    if (write(fd, rules, RULE_SIZE*count) != RULE_SIZE*count){
        perror("Error writing file");
    }
    close(fd);
}

/* load rules from a file and write them to the char device */
void load_rules(const char * path){
    FILE *fp;
    int count;
    rule_t rules[MAX_RULES];

    fp = fopen(path, "r");
    if (!fp){
        perror("Error opening file");
        return;
    }

    count = parse_rules(fp, rules);
    fclose(fp);

    if (count > 0)
        write_rules(rules, count);
}

/* show all hosts from the sysfs device to the user */
void show_hosts(){
    FILE *fp;
    int c;
    fp = fopen(SYSFS_PATH("fw_hosts/hosts"), "r");
    if (fp < 0){
        perror("Error opening file");
        return;
    }
    while ((c = getc(fp)) != EOF){
        putchar(c);
    }
    fclose(fp);
}

/* copy hosts from a file to the sysfs device */
void load_hosts(const char * path){
    struct stat file_stat;
    int src, dst;

    src = open(path, O_RDONLY);
    if (!src){
        perror("Error opening file");
        return;
    }
    if (fstat(src, &file_stat)){
        perror("Error reading file stat");
        close(src);
        return;
    }
    if (file_stat.st_size >= getpagesize()){
        printf("Hosts list is too large, maximum size is %d\n", getpagesize());
        close(src);
        return;
    }

    dst = open(SYSFS_PATH("fw_hosts/hosts"), O_WRONLY);
    if (dst<0){
        perror("Error opening file");
        close(src);
        return;
    }
    if (sendfile(dst, src, NULL, file_stat.st_size)<0){
        perror("Error copying host list");
    }

    close(src);
    close(dst);
}

/* print a connection entry */
void print_con(connection con){
    char src_ip[16], dst_ip[16]; // max ip length: 4*3+3*1=15
    inet_ntop(AF_INET, &con.src_ip, src_ip, 16); //convert the ips to strings
    inet_ntop(AF_INET, &con.dst_ip, dst_ip, 16);
    printf("%-15s\t%hu\t\t%-15s\t%hu\t\t%s\n",
        src_ip, ntohs(con.src_port), dst_ip, ntohs(con.dst_port), state_to_s(con.src_state));
    printf("%-15s\t%hu\t\t%-15s\t%hu\t\t%s\n",
        dst_ip, ntohs(con.dst_port), src_ip, ntohs(con.src_port), state_to_s(con.dst_state));
}

/* print the connection table */
void show_conn_tab(void){
    int fd;
    connection con;
    fd = open(DEV_PATH("conn_tab"), O_RDONLY);
    if (fd<0){
        perror("Error opening file");
        return;
    }
    printf("src_ip\t\tsrc_port\tdst_ip\t\tdst_port\tstate\n");
    while (read(fd, &con, sizeof(connection)) == sizeof(connection)) { //read the log con by con and print them
        print_con(con);
    }
    close(fd);
}

int main(int argc, char const *argv[]){
    if (argc > 3 || argc == 1){
        printf("Invalid number of arguments.\n");
        return -1;
    }
    if (!strcmp(argv[1], "activate")){
        write_char(SYSFS_PATH("fw_rules/active"), "1");
        return 0;
    }
    if (!strcmp(argv[1], "deactivate")){
        write_char(SYSFS_PATH("fw_rules/active"), "0");
        return 0;
    }
    if (!strcmp(argv[1], "show_rules")){
        show_rules();
        return 0;
    }
    if (!strcmp(argv[1], "clear_rules")){
        write_char(SYSFS_PATH("fw_rules/rules_clear"), "1");
        return 0;
    }
    if (!strcmp(argv[1], "load_rules") && argc == 3){
        load_rules(argv[2]);
        return 0;
    }
    if (!strcmp(argv[1], "show_hosts")){
        show_hosts();
        return 0;
    }
    if (!strcmp(argv[1], "load_hosts") && argc == 3){
        load_hosts(argv[2]);
        return 0;
    }
    if (!strcmp(argv[1], "show_log")){
        show_log();
        return 0;
    }
    if (!strcmp(argv[1], "clear_log")){
        write_char(SYSFS_PATH("fw_log/log_clear"), "1");
        return 0;
    }
    if (!strcmp(argv[1], "show_conn_tab")){
        show_conn_tab();
        return 0;
    }
    printf("Invalid argument.\n");
    return -1;
}
