#ifndef _UTIL_H_
#define _UTIL_H_

int safe_device_init(const char *name, const struct file_operations *fops,
                     struct device *dev, struct device_attribute *attrs);
void safe_device_cleanup(int major_number, int step, struct device *dev,
                         struct device_attribute *attrs);

#endif
