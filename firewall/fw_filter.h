#ifndef FW_FILTER_H
#define FW_FILTER_H

#define NUM_HOOKS 3

/************************************
 * Firewall filter "public" methods *
 ************************************/

/* Resets all the packet counters to 0 */
void reset_counters(void);

/* Returns the packet counter indicated by the first letter:
 * [t]otal
 * [b]locked
 * [p]assed
 * or -1 otherwise
 */
int get_counter(char);

/* initialize the firewall - reset counters, set up and register hooks.
 * returns 0 on success, negative error otherwise
 */
int init_firewall(void);

/* cleanup the firewall - unregister hooks */
void cleanup_firewall(void);
#endif
