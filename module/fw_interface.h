#ifndef FW_INTERFACE_H
#define FW_INTERFACE_H
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "firewall.h" // so we can talk to the firewall for counters

#define CHARDEV_NAME "stats"
#define CLASS_NAME "FW_interface"

/***********************************************
 * Firewall sysfs interface - "public" methods *
 ***********************************************/

/* creates the sysfs device and its attributes.
 * on failure it cleans up after itself and returns a negative number.
 * return 0 on success.
 */
int init_sysfs(void);

/* Clean up the sysfs device starting from the stage passed in the parameter.
 * This is so we can reuse the code in init_sysfs in case it fails in the
 * process of creating the device. Passing 3 cleans everything.
 */
void cleanup_sysfs(int);

#endif
