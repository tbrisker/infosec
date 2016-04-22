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

// auxiliary strings, for your convenience
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
} minor_t;


#endif // _FW_H_
