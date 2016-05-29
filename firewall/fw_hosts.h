#ifndef FW_HOSTS_H
#define FW_HOSTS_H

#define DEVICE_NAME_HOSTS "hosts"

__u8 check_hosts(char *host);

int init_hosts(void);
void cleanup_hosts(void);

#endif
