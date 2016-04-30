#ifndef UTIL_H
#define UTIL_H
extern char time_str[21];
extern char reason_str[5];

int s_to_ip_and_mask(char *str, int *ip);

int read_int(char *path);

void write_char(char *path, const char *c);

char * time_to_s(long timestamp);

char * prot_to_s(int protocol);

char * action_to_s(char action);

char * reason_to_s(int reason);

#endif
