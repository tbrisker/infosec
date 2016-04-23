#ifndef FW_STATS_H
#define FW_STATS_H

#define DEVICE_NAME_STATS "stats"

/***********************************************
 * Firewall stats interface - "public" methods *
 ***********************************************/

/* creates the sysfs device and its attributes.
 * on failure it cleans up after itself and returns a negative number.
 * return 0 on success.
 */
int init_stats(void);

/* Clean up the sysfs device starting from the stage passed in the parameter.
 * This is so we can reuse the code in init_sysfs in case it fails in the
 * process of creating the device. Passing 3 cleans everything.
 */
void cleanup_stats(void);

extern unsigned int p_total, p_block, p_pass;

#endif
