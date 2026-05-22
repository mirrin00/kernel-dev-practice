#include "linux/printk.h"
#include <linux/kern_levels.h>
#include <linux/stat.h>
#include <linux/moduleparam.h>
#include <linux/module.h>

static char *my_str = "<placeholder>";
static int my_int = -1;
static uint my_uint = 0;
static long my_long = -1;
static ulong my_ulong = 0;
static bool my_bool = false;

static uint range = 5;

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello %s!\n", my_str);
    printk(KERN_WARNING "Hello, my first WARN\n");
    printk(KERN_ERR "Hello, my first ERR\n");
    // =====
    printk(KERN_INFO "my_int=%d\n", my_int);
    printk(KERN_INFO "my_uint=%u\n", my_uint);
    printk(KERN_INFO "my_long=%ld\n", my_long);
    printk(KERN_INFO "my_int=%lu\n", my_ulong);
    printk(KERN_INFO "my_bool=%d\n", my_bool);
    printk(KERN_INFO "range=%d\n", range);
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_INFO "Goodbye Cruel %s!\n", my_str);
    printk(KERN_INFO "my_int=%d\n", my_int);
    printk(KERN_INFO "my_uint=%u\n", my_uint);
    printk(KERN_INFO "my_long=%ld\n", my_long);
    printk(KERN_INFO "my_ulong=%lu\n", my_ulong);
    printk(KERN_INFO "my_bool=%d\n", my_bool);
    printk(KERN_INFO "range=%d\n", range);
}

// Define module parameter
module_param(my_str, charp, S_IRUSR);
MODULE_PARM_DESC(my_str, "String for use");

module_param(my_int, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(my_int, "Int parameter example");

module_param(my_uint, uint, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(my_uint, "Uint parameter example");

module_param(my_long, long, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(my_long, "Long parameter example");

module_param(my_ulong, ulong, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(my_ulong, "Ulong parameter example");

module_param(my_bool, bool, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(my_bool, "Bool parameter example");

static int set_range(const char *val, const struct kernel_param *kp)
{
    int ival;
    int err = kstrtoint(val, 10, &ival);
    if (err) {
        printk(KERN_ERR "Can't parse %s\n", val);
        return -EINVAL;
    }
    if (ival < -5 || ival > 10) {
        printk(KERN_ERR "Value %d outside of range\n", ival);
        return -EINVAL;
    }
    printk(KERN_INFO "Setting value %s to %d\n", kp->name, ival);
    *(int *)kp->arg = ival;
    return 0;
}

static struct kernel_param_ops range_cbs = {
    .set = set_range,
    .get = param_get_int,
};

module_param_cb(range, &range_cbs, &range, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(range, "Range parameter example");

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");