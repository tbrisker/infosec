#ifndef UTIL_H
#define UTIL_H

int read_int(char * path);

void write_char(char *path, const char *c);

char * time_to_s(long timestamp);

char * prot_to_s(unsigned char protocol);
int s_to_prot(char * str);

char * action_to_s(char action);
int s_to_action(char * str);

char * dir_to_s(int dir);
int s_to_dir(char *str);

int s_to_ip_and_mask(char *str, unsigned int *ip);
char * ip_and_mask_to_s(unsigned int ip, int mask);

char s_to_ack(char *str);
char * ack_to_s(char ack);

char * reason_to_s(int reason);

int s_to_port(char *str);
char * port_to_s(unsigned short port);

#endif
