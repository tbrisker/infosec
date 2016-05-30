#ifndef FW_HOSTS_H
#define FW_HOSTS_H

#define DEVICE_NAME_HOSTS "hosts"

/* Blocked host list module public interface */

/* check if a given host is in the blocked list */
int check_hosts(char *host);

/*init and cleanup the module and its device */
int init_hosts(void);
void cleanup_hosts(void);

#endif
