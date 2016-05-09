#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/time.h>
//include all our modules
#include "fw_filter.h"
#include "fw_stats.h"
#include "fw_log.h"
#include "fw_rules.h"
#include "util.h"

// auxiliary strings, for your convenience
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"

extern struct class *sysfs_class; //we register all devices under a single class
#endif // _FW_H_
