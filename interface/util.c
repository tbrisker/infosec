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

/* return a string representing the timestamp */
char time_str[21];
char * time_to_s(long timestamp){
    struct tm* parsed = localtime(&timestamp);
    if (strftime(time_str, 20, "%d/%m/%Y %T", parsed))
        return time_str;
    return "Error";
}

/* convert protocol number to string */
char * prot_to_s(unsigned char protocol){
    switch (protocol){
    case PROT_ICMP:
        return "ICMP";
    case PROT_TCP:
        return "TCP";
    case PROT_UDP:
        return "UDP";
    case PROT_ANY:
        return "any";
    default:
        return "other";
    }
}

/* convert protocol string to number */
int s_to_prot(char * str){
    if (!strcmp(str, "ICMP"))
        return PROT_ICMP;
    if (!strcmp(str, "TCP"))
        return PROT_TCP;
    if (!strcmp(str, "UDP"))
        return PROT_UDP;
    if (!strcmp(str, "any"))
        return PROT_ANY;
    if (!strcmp(str, "other"))
        return PROT_OTHER;
    printf("Invalid protocol %s\n", str);
    return -1;
}

/* convert netfilter action to string */
char * action_to_s(char action){
    return action ? "accept" : "drop";
}

/* convert string to netfilter action */
int s_to_action(char * str){
    if (!strcmp(str, "accept"))
        return NF_ACCEPT;
    if (!strcmp(str, "drop"))
        return NF_DROP;
    printf("Invalid action %s\n", str);
    return -1;
}

/* convert direction number to string */
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

/* convert direction string to number */
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

/* Convert a string to ip and mask size */
/* returns the mask size or -1 on error */
int s_to_ip_and_mask(char *str, unsigned int *ip){
    struct in_addr addr = {0};
    char *nps;
    int mask = 32; //default to single host
    if (!strcmp(str, "any")){
        *ip = 0; // 0.0.0.0/0 will be used to denote "any" ip as is common.
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

/* convert an ip and mask to nice string representation */
char ip_and_mask[20];
char * ip_and_mask_to_s(unsigned int ip, int mask){
    struct in_addr addr = {ip};
    char mask_s[4];

    if ((ip == 0) || (mask == 0))
        return "any";

    strcpy(ip_and_mask, inet_ntoa(addr));
    if (mask>0 && mask<32){
        sprintf(mask_s, "/%d", mask);
        strcat(ip_and_mask, mask_s);
    }
    return ip_and_mask;
}

/* convert string to ack number */
char s_to_ack(char *str){
    if (!strcmp(str, "yes"))
        return ACK_YES;
    if (!strcmp(str, "no"))
        return ACK_NO;
    if (!strcmp(str, "any"))
        return ACK_ANY;
    printf("Invalid ack %s!", str);
    return -1;
}

/* convert ack number to string */
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

/* convert reason to string */
char reason_str[5];
char * reason_to_s(reason_t reason){
    switch (reason){
    case REASON_FW_INACTIVE:
        return "FW_INACTIVE";
    case REASON_NO_MATCHING_RULE:
        return "NO_MATCHING_RULE";
    case REASON_XMAS_PACKET:
        return "XMAS_PACKET";
    case REASON_ILLEGAL_VALUE:
        return "ILLEGAL_VALUE";
    case REASON_CONN_EXIST:
        return "CONN_EXIST";
    case REASON_CONN_NOT_EXIST:
        return "CONN_NOT_EXIST";
    case REASON_TCP_NON_COMPLIANT:
        return "TCP_NON_COMPLIANT";
    case REASON_BLOCKED_HOST:
        return "BLOCKED_HOST";
    default:
        snprintf(reason_str, 5, "%d", reason);
    }
    return reason_str;
}

/* convert string to port number */
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

/* convert port number to string */
char port_s[6];
char * port_to_s(unsigned short port){
    switch (port){
    case PORT_ANY:
        return "any";
    case PORT_ABOVE_1023:
        return ">1023";
    default:
        if (snprintf(port_s, 6, "%hu", port) > 0)
            return port_s;
    }
    return "ERR";
}

char * state_to_s(conn_state state){
    switch (state){
    case C_CLOSED:
        return "CLOSED";
    case C_LISTEN:
        return "LISTEN";
    case C_SYN_SENT:
        return "SYN_SENT";
    case C_SYN_RECEIVED:
        return "SYN_RECEIVED";
    case C_ESTABLISHED:
        return "ESTABLISHED";
    case C_CLOSE_WAIT:
        return "CLOSE_WAIT";
    case C_LAST_ACK:
        return "LAST_ACK";
    case C_FIN_WAIT_1:
        return "FIN_WAIT_1";
    case C_FIN_WAIT_2:
        return "FIN_WAIT_2";
    case C_CLOSING:
        return "CLOSING";
    case C_TIME_WAIT:
        return "TIME_WAIT";
    }
    return "ERR";
}
