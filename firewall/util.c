/* These are taken from drivers/base/core.c to ease attribute registration -
 * since we register all devices with the same class, we can't use the default
 * class attributes as we have in the previous exercise. These are originally
 * defined as static, so we can't use the original methods.
 */
int device_add_attributes(struct device *dev,
                 struct device_attribute *attrs)
{
    int error = 0;
    int i;

    if (attrs) {
        for (i = 0; attr_name(attrs[i]); i++) {
            error = device_create_file(dev, &attrs[i]);
            if (error)
                break;
        }
        if (error)
            while (--i >= 0)
                device_remove_file(dev, &attrs[i]);
    }
    return error;
}

void device_remove_attributes(struct device *dev,
                     struct device_attribute *attrs)
{
    int i;

    if (attrs)
        for (i = 0; attr_name(attrs[i]); i++)
            device_remove_file(dev, &attrs[i]);
}
