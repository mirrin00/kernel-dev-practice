#include <linux/kern_levels.h>
#include <linux/stat.h>
#include <linux/moduleparam.h>
#include <linux/module.h>

static char *my_str = "<placeholder>";

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello %s!\n", my_str);
    printk(KERN_WARNING "Hello, my first WARN\n");
    printk(KERN_ERR "Hello, my first ERR\n");
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_INFO "Goodbye Cruel %s!\n", my_str);
}

// Define module parameter
module_param(my_str, charp, S_IRUSR);
MODULE_PARM_DESC(my_str, "String for use");

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");