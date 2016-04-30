#include "main.h"

void print_log_row(log_row_t row){
    char src_ip[16], dst_ip[16]; // max ip length: 4*3+3*1=15
    inet_ntop(AF_INET, &row.src_ip, src_ip, 16);
    inet_ntop(AF_INET, &row.dst_ip, dst_ip, 16);
    printf("%s\t%-15s\t%-15s\t%hu\t\t%hu\t\t%s\t\t%hhu\t%s\t%hu\t%u\n",
           time_to_s(row.timestamp), src_ip, dst_ip,
           ntohs(row.src_port), ntohs(row.dst_port),
           prot_to_s(row.protocol), row.hooknum, action_to_s(row.action),
           row.reason, row.count);
}

void show_log(void){
    int fd;
    fd = open(DEV_PATH("log"), O_RDONLY);
    if (fd<0){
        perror("Error opening file");
        return;
    }
    printf("timestamp\t\tsrc_ip\t\tdst_ip\t\tsrc_port\tdst_port\tprotocol\thooknum\taction\treason\tcount\n");
    log_row_t row;
    while (read(fd, &row, sizeof(log_row_t)) == sizeof(log_row_t)) {
        print_log_row(row);
    }
    close(fd);
}
loopback any 127.0.0.1/8 127.0.0.1/8 any any any any accept

void print_rule(rule_t rule){
    printf("%s %s %s %s %s %s %s %s %s\n",
        rule.name, dir_to_s(rule.direction));
}

void show_rules(int count){
    int fd,i;
    rule_t rules[count];
    fd = open(DEV_PATH("rules"), O_RDONLY);
    if (fd<0){
        perror("Error opening file");
        return;
    }
    if (read(fd, &rules, sizeof(rule_t)*count) == sizeof(rule_t)*count) {
        for (i = 0; i < count; ++i)
            print_rule(rules[i]);
    }
    close(fd);
}

void load_rules(const char * path){

}

int main(int argc, char const *argv[]){
    int count;
    int ip, mask;
    char str[] = "192.168.1.1/24";
    mask = s_to_ip_and_mask(str, &ip);
    printf("%d/%d\n", ip, mask);
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
        count = read_int(SYSFS_PATH("fw_rules/rules_size"));
        if (count > 0)
            show_rules(count);
        return 0;
    }
    if (!strcmp(argv[1], "clear_rules")){
        write_char(SYSFS_PATH("fw_rules/rules_clear"), "1");
        return 0;
    }
    if (!strcmp(argv[1], "load_rules") && argc == 2){
        load_rules(argv[2]);
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
    printf("Invalid argument.\n");
    return -1;
    return 0;
}
