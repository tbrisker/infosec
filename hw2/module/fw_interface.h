#ifndef FW_INTERFACE_H
#define FW_INTERFACE_H
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "firewall.h"

#define CHARDEV_NAME "stats"
#define CLASS_NAME "FW_interface"

int cleanup_sysfs(int);
int init_sysfs(void);

#endif
