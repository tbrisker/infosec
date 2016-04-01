#ifndef FIREWALL_H
#define FIREWALL_H
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define NUM_HOOKS 3

void reset_counters(void);
unsigned int get_counter(char);

int init_firewall(void);
void cleanup_firewall(void);
#endif
