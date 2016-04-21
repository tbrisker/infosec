#ifndef _UTIL_H_
#define _UTIL_H_

int device_add_attributes(struct device *dev, struct device_attribute *attrs);
void device_remove_attributes(struct device *dev, struct device_attribute *attrs);

#endif
