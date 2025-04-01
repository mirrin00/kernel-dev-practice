#include <linux/lockdep.h>
#include <linux/bitops.h>
#include <linux/gfp_types.h>
#include <linux/kern_levels.h>
#include <linux/stat.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/mutex.h>

// Macros for logging
#define MOD_PRFX "sanitizers: "
#define MOD_DEBUG(fmt, ...) pr_debug(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_INFO(fmt, ...) pr_info(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_WARN(fmt, ...) pr_warn(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_ERR(fmt, ...) pr_err(MOD_PRFX fmt "\n", ##__VA_ARGS__)

enum {
    KASAN_ERR = 0,
    MEMLEAK_ERR,
    LOCKDEP_ERR1,
    LOCKDEP_ERR2,
};

#define DEFAULT_SIZE (10)

static ulong error_type = 0;
static uint user_arr_size = DEFAULT_SIZE;

// ====

static uint arr_size;
static char *arr;
DEFINE_MUTEX(arr_lock);
// struct mutex arr_lock;

static ssize_t work_show(struct kobject *kobj,
                         struct kobj_attribute *attr, char *buf)
{
    strncpy(buf, arr, arr_size);
    return arr_size;
}

static int check_arr_size(void)
{
    char *narr;

    lockdep_assert_held(&arr_lock);
    if (arr_size == user_arr_size)
        return 0;

    // krealloc can be used here
    narr = test_bit(LOCKDEP_ERR2, &error_type) ? MOD_WARN("LOCKDEP ERR Type 2 is enanbled"), NULL\
        : kzalloc(user_arr_size, GFP_KERNEL);
    if (!narr)
        return -ENOMEM;
    memcpy(narr, arr, arr_size);
    // Look at here
    test_bit(MEMLEAK_ERR, &error_type) ? arr = narr, MOD_WARN("MEMLEAK ERR is enanbled")\
        : kfree(arr), arr = narr;
    arr_size = user_arr_size;
    return 0;
}

static int update_arr(const char *buf, size_t count)
{
    int err;

    if (!test_bit(LOCKDEP_ERR1, &error_type))
        mutex_lock(&arr_lock);
    else
        MOD_WARN("LOCKDEP ERR Type 1 is enanbled");

    err = check_arr_size();
    if (err) {
        if (test_bit(LOCKDEP_ERR2, &error_type))
            return err;

        goto err_update;
    }

    memcpy(arr, buf, count);
err_update:
    if (!test_bit(LOCKDEP_ERR1, &error_type))
        mutex_unlock(&arr_lock);
    return err;
}

static ssize_t work_store(struct kobject *kobj,
                          struct kobj_attribute *attr, const char *buf,
                          size_t count)
{
    int err;
    size_t new_count;
    if (test_bit(KASAN_ERR, &error_type)) {
        new_count = count > arr_size - 1 ? arr_size - 1 : count;
        MOD_WARN("KASAN ERR is enabled");
    } else {
        new_count = count > user_arr_size - 1 ? user_arr_size - 1 : count;
    }
    err = update_arr(buf, new_count);
    return err ? err : count;
}

static const struct kobj_attribute work_entry_attr = {
    .attr = {
        .name = "do_work",
        .mode = S_IRUGO | S_IWUGO,
    },
    .show = work_show,
    .store = work_store,
};

// ====

static int __init hello_init(void)
{
    int err;

    arr_size = user_arr_size;
    arr = kzalloc(arr_size, GFP_KERNEL);
    if (!arr) {
        err = -ENOMEM;
        goto init_err;
    }

    if ((err = sysfs_create_file(&THIS_MODULE->mkobj.kobj, &work_entry_attr.attr))) {
        MOD_ERR("Can't create pid file in sysfs, err %d", err);
        goto init_err;
    }
    MOD_INFO("Module loaded");
    return 0;
init_err:
    return err;
}

static void __exit hello_exit(void)
{
    sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &work_entry_attr.attr);
    MOD_INFO("Module unloaded");
}

// Define module parameter
module_param(error_type, ulong, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(error_type, "Flags to activate errors");

module_param(user_arr_size, uint, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(user_arr_size, "Set size of internal array");

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");