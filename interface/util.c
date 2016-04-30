#include "main.h"

/**************/
/* File utils */
/**************/

/* get an int from a file or -1 on error */
/* we take advantage of the stdlib here to parse the data */
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
void write_char(char *path, const char *c){
    int fd;
    fd = open(path, O_WRONLY);
    if (fd<0){
        perror("Error opening file");
        return;
    }
    if (write(fd, c, 1) != 1){
        perror("Error writing file");
    }
    close(fd);
}


/********************/
/* Conversion utils */
/********************/

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

int s_to_prot(char * str){
    if (!strcmp(str, "icmp"))
        return PROT_ICMP;
    if (!strcmp(str, "tcp"))
        return PROT_TCP;
    if (!strcmp(str, "udp"))
        return PROT_UDP;
    if (!strcmp(str, "any"))
        return PROT_ANY;
    if (!strcmp(str, "other"))
        return PROT_OTHER;
    printf("Invalid protocol %s!\n", str);
    return -1;
}

char * action_to_s(char action){
    return action ? "accept" : "drop";
}

int s_to_action(char * str){
    if (!strcmp(str, "accept"))
        return NF_ACCEPT;
    if (!strcmp(str, "drop"))
        return NF_DROP;
    printf("Invalid action %s!", str);
    return -1;
}

char * dir_to_s(int dir){
    switch(dir){
    case DIRECTION_IN:
        return "in";
    case DIRECTION_OUT:
        return "out";
    case DIRECTION_ANY:
        return "any";
    }
    return "ERR";
}

int s_to_dir(char *str){
    if (!strcmp(str, "in"))
        return DIRECTION_IN;
    if (!strcmp(str, "out"))
        return DIRECTION_OUT;
    if (!strcmp(str, "any"))
        return DIRECTION_ANY;
    printf("Invalid action %s!", str);
    return -1;
}

/* Convert a string to ip and mask */
int s_to_ip_and_mask(char *str, int *ip){
    struct in_addr addr = {0};
    char *nps;
    int mask = 0;
    if (!strcmp(str, "any")){
        *ip = 0; // 0.0.0.0 will be used to denote "any" ip as is common.
        return 0;
    }
    nps = strchr(str, '/');
    if (nps != NULL){
        *nps = '\0';  //split the nps from the ip so they can be parsed seperately
        nps++;
        if (sscanf(nps, "%d", &mask) != 1 || mask > 32 || mask < 0){
            printf("Invalid ip %s/%s\n", str, nps);
            return -1;
        }
    }
    if (!inet_aton(str, &addr)){
        printf("Invalid ip %s\n", str);
        return -1;
    }
    *ip = addr.s_addr;
    return mask;
}

char ip_and_mask[20];
char * ip_and_mask_to_s(int ip, int mask){
    struct in_addr addr = {ip};
    char mask_s[4];
    strcpy(ip_and_mask, inet_ntoa(addr));
    if (mask>0 && mask <=32){
        sprintf(mask_s, "/%d", mask);
        strcat(ip_and_mask, mask_s);
    }
    return ip_and_mask;
}

char ack_to_chr(char *str){
    if (!strcmp(str, "yes"))
        return ACK_YES;
    if (!strcmp(str, "no"))
        return ACK_NO;
    if (!strcmp(str, "any"))
        return ACK_ANY;
    printf("Invalid ack %s!", str);
    return -1;
}

char * ack_to_s(char ack){
    switch(ack){
    case ACK_YES:
        return "yes";
    case ACK_NO:
        return "no";
    case ACK_ANY:
        return "any";
    default:
        return "ERR";
    }
}



char reason_str[5];
char * reason_to_s(int reason){
    switch (reason){
    case REASON_FW_INACTIVE:
        return "REASON_FW_INACTIVE";
        break;
    case REASON_NO_MATCHING_RULE:
        return "REASON_NO_MATCHING_RULE";
        break;
    case REASON_XMAS_PACKET:
        return "REASON_XMAS_PACKET";
        break;
    case REASON_ILLEGAL_VALUE:
        return "REASON_ILLEGAL_VALUE";
        break;
    default:
        snprintf(reason_str, 5, "%d", reason);
    }
    return reason_str;
}

int s_to_port(char *str){
    unsigned short port;
    if (!strcmp(str, "any"))
        return PORT_ANY;
    if (!strcmp(str, ">1023"))
        return PORT_ABOVE_1023;
    if (sscanf(str, "%hu", &port) == 1 && port < 1024)
        return port;
    return -1;
}

char port_s[6];
char * port_to_s(unsigned short port){
    switch (port){
    case PORT_ANY:
        return "any";
    case PORT_ABOVE_1023:
        return ">1023";
    default:
        if (sprintf(port_s, "%hu", port) == 1)
            return port_s;
    }
    return "ERR";
}
