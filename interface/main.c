#include "main.h"

/* get an int from a file or -1 on error */
int read_int(char * path){
    int val = -1;
    FILE * fp;
    fp = fopen(path, "r");
    if (!fp){
        perror("Error opening file");
        return val;
    }
    if (fscanf(fp, "%d", &val) != 1){
        perror("Error reading file");
    }
    fclose(fp);
    return val;
}

/* write a char to a file */
void write_char(char * path, char c){
    FILE * fp;
    fp = fopen(path, "w");
    if (!fp){
        perror("Error opening file");
        return;
    }
    if (fprintf(fp, "%c", c) < 0){
        perror("Error writing file");
    }
    fclose(fp);
}

//convert
char * ip_to_s(int ip){
    struct in_addr addr = {ip};
    return inet_ntoa(addr);
}

char time_str[21];
char * time_to_s(long timestamp){
    struct tm* parsed = localtime(&timestamp);
    if (strftime(time_str, 20, "%d/%m/%Y %T", parsed))
        return time_str;
    return "Error";
}

char * prot_to_s(int protocol){
    switch (protocol){
    case PROT_ICMP:
        return "icmp";
    case PROT_TCP:
        return "tcp";
    case PROT_UDP:
        return "udp";
    default:
        return "other";
    }
}

char * action_to_s(char action){
    return action ? "accept" : "drop";
}

void print_log_row(log_row_t row){
    char src_ip[16], dst_ip[16];
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
    fd = open(DEV_PATH(log), O_RDONLY);
    if (fd<0){
        perror("Error opening file");
        return;
    }
    printf("timestamp\t\tsrc_ip\t\tdst_ip\t\tsrc_port\tdst_port\tprotocol\thooknum\taction\treason\tcount\n");
    log_row_t row;
    while (read(fd, &row, sizeof(log_row_t))== sizeof(log_row_t)) {
        print_log_row(row);
    }
    close(fd);
}

int main(int argc, char const *argv[]){
    // if (argc > 3 || argc == 1){
    //     printf("Invalid number of arguments.\n");
    //     return -1;
    // }
    // if (!strcmp(argv[1], "show_log")){
    //     show_log();
    //     return 0;
    // }
    // printf("Invalid argument.\n");
    // return -1;
    show_log();
    return 0;
}
