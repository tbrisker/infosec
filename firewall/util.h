#ifndef _UTIL_H_
#define _UTIL_H_

/* function to easily create a device */
int safe_device_init(const char *name, const struct file_operations *fops,
                     struct device *dev, struct device_attribute *attrs);
/* function to easily clean up after a device */
void safe_device_cleanup(int major_number, int step, struct device *dev,
                         struct device_attribute *attrs);
/* macro for printing error messages */
#define PERR(message) printk(KERN_ERR message " with error: %d\n", err)

#endif
