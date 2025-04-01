#include "asm-generic/errno-base.h"
#include "linux/completion.h"
#include "linux/container_of.h"
#include "linux/jiffies.h"
#include "linux/kernel.h"
#include "linux/kstrtox.h"
#include "linux/kthread.h"
#include "linux/list.h"
#include "linux/sched.h"
#include "linux/sched/task.h"
#include "linux/signal.h"
#include "linux/slab.h"
#include "linux/spinlock.h"
#include "linux/spinlock_types.h"
#include "linux/sysfs.h"
#include "linux/timer.h"
#include "linux/types.h"
#include "linux/workqueue.h"
#include "linux/workqueue_types.h"
#include <linux/lockdep.h>
#include <linux/bitops.h>
#include <linux/gfp_types.h>
#include <linux/kern_levels.h>
#include <linux/stat.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/delay.h>

// Macros for logging
#define MOD_PRFX "queue: "
#define MOD_DEBUG(fmt, ...) pr_debug(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_INFO(fmt, ...) pr_info(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_WARN(fmt, ...) pr_warn(MOD_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_ERR(fmt, ...) pr_err(MOD_PRFX fmt "\n", ##__VA_ARGS__)

// Module params

static ulong dins_ms = 5000;
static ulong thread_sleep_ms = 5000;
static bool thread_active_sleep = false;
static bool use_refcnt = false;

// =============
// Structures

enum oper {
    INSERT,
    DELAYED_INSERT,
    SPAWN_MULTI,
    RUN_THREAD,
    SELF_DTR,
    EXT_WORK,
    UNKNOWN,
};

struct __str_to_oper {
    const char *name;
    size_t len;
    enum oper op;
};

#define __STR_TO_OPER(name, op) { name, sizeof(name) - 1, op }
#define STR_TO_OPER(name, op) __STR_TO_OPER(name": ", op)

static struct __str_to_oper str_to_op[] = {
    STR_TO_OPER("insert", INSERT),
    STR_TO_OPER("delayed_ins", DELAYED_INSERT),
    STR_TO_OPER("spawn_multi", SPAWN_MULTI),
    STR_TO_OPER("run_bg", RUN_THREAD),
    STR_TO_OPER("self_dtr", SELF_DTR),
    STR_TO_OPER("ext_work", EXT_WORK),
    {NULL, 0, UNKNOWN},
};

#define MAX_ENTRY_NAME (40)

enum entry_state {
    ENTRY_CLEAN,
    ENTRY_UNDDER_WORK,
    ENTRY_END_WORK,
};

struct my_entry {
    struct list_head list;
    char name[MAX_ENTRY_NAME];
    // delayed insert
    struct delayed_work dwork;
    // spawn
    struct work_struct work;
    // self_dtr timer
    struct timer_list timer;
    // refcnt
    struct kref refcnt;
    // completion + atomic
    atomic_t state;
    struct completion work_end;
};

#define MAX_WQ_WORKS (5)

// === Global vars ===

LIST_HEAD(my_queue);
DEFINE_SPINLOCK(queue_lock);
struct workqueue_struct *wq;
struct task_struct *bg_thread;
struct kmem_cache *entry_cache;

// === functions ===

#define __kfree_entry(entry) kfree(entry)
#define __kmemcache_free_entry(entry) kmem_cache_free(entry_cache, entry)

#define free_entry(entry) __kmemcache_free_entry(entry)

static struct my_entry * __make_entry(const char *name)
{
    // struct my_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    struct my_entry *entry = kmem_cache_zalloc(entry_cache, GFP_KERNEL);

    if (!entry)
        return ERR_PTR(-ENOMEM);

    strcpy(entry->name, name);
    INIT_LIST_HEAD(&entry->list);

    if (use_refcnt) {
        kref_init(&entry->refcnt);
    }

    init_completion(&entry->work_end);
    atomic_set(&entry->state, ENTRY_CLEAN);

    return entry;
}

static void release_entry(struct kref *kref)
{
    struct my_entry *e = container_of(kref, struct my_entry, refcnt);
    MOD_INFO("Releasing entry %p", e);
    free_entry(e);
}

// INSERT

static int insert_to_queue(const char *name)
{
    struct my_entry *entry = __make_entry(name);

    if (IS_ERR(entry))
        return PTR_ERR(entry);
    
    spin_lock(&queue_lock);
    list_add_tail(&entry->list, &my_queue);
    spin_unlock(&queue_lock);

    return 0;
}

// DELAYED_INSERT

static void delayed_insert_work(struct work_struct *work)
{
    struct delayed_work *dwork = container_of(work, struct delayed_work, work);
    struct my_entry *entry = container_of(dwork, struct my_entry, dwork);

    spin_lock(&queue_lock);
    list_add_tail(&entry->list, &my_queue);
    spin_unlock(&queue_lock);
}

static int delayed_insert(const char *name)
{
    struct my_entry *entry = __make_entry(name);
    ulong delay;

    if (IS_ERR(entry))
        return PTR_ERR(entry);

    INIT_DELAYED_WORK(&entry->dwork, delayed_insert_work);

    if (sscanf(entry->name, "%lu", &delay) != 1) {
        MOD_WARN("Delayed cmd does not contain time");
        delay = dins_ms;
    }

    queue_delayed_work(wq, &entry->dwork, msecs_to_jiffies(delay));

    return 0;
}

// SPAWN_MULTI

static void __spawn_insert_work(struct work_struct *work)
{
    struct my_entry *entry = container_of(work, struct my_entry, work);

    spin_lock(&queue_lock);
    list_add_tail(&entry->list, &my_queue);
    spin_unlock(&queue_lock);
}

static int spawn_multi(const char *name)
{
    char work_name[MAX_ENTRY_NAME];
    uint count, i;
    struct my_entry *entry;

    if (kstrtouint(name, 10, &count)) {
        MOD_WARN("spawn contains no uint");
        count = MAX_WQ_WORKS * 3;
    }

    for (i = 0; i < count; i++) {
        snprintf(work_name, MAX_ENTRY_NAME, "spawn%u", i);
        entry = __make_entry(work_name);
        if (IS_ERR(entry)) {
            int err = PTR_ERR(entry);
            MOD_ERR("Cannot create entry, %d", err);
            return err;
        }

        INIT_WORK(&entry->work, __spawn_insert_work);
        queue_work(wq, &entry->work);
    }

    return 0;
}

// CLEANUP

static void clean_queue(void)
{
    struct list_head *pos, *n;
    MOD_INFO("Cleaning queue...");

    spin_lock(&queue_lock);

    list_for_each_safe(pos, n, &my_queue) {
        struct my_entry *e = container_of(pos, struct my_entry, list);
        MOD_INFO("Deleting '%s' entry", e->name);
        list_del_init(pos);
        if (use_refcnt)
            kref_put(&e->refcnt, release_entry);
        else
            free_entry(e);
    }

    spin_unlock(&queue_lock);
}

// Background kthread

static int bg_work(void *data)
{
    struct my_entry *entry;

    MOD_INFO("Background thread started");
    while (!kthread_should_stop()) {
        spin_lock(&queue_lock);

        if (list_empty(&my_queue)) {
            MOD_INFO("List is empty, nothing to do");
        } else {
            entry = list_first_entry(&my_queue, struct my_entry, list);
            // Check state and wait for completion
            if (atomic_read(&entry->state) == ENTRY_UNDDER_WORK) {
                // SPINLOCK!!!
                spin_unlock(&queue_lock);

                MOD_INFO("bg_work: Waiting for completion, entry %p", entry);
                wait_for_completion(&entry->work_end);

                spin_lock(&queue_lock);
            }
            // delete + init (for timer)
            list_del_init(&entry->list);
            MOD_INFO("Deleted element '%s'", entry->name);
            if (use_refcnt) {
                kref_put(&entry->refcnt, release_entry);
                MOD_INFO("Using refcnt");
            } else {
                free_entry(entry);
            }
        }

        spin_unlock(&queue_lock);

        if (thread_active_sleep)
            mdelay(thread_sleep_ms);
        else
            msleep(thread_sleep_ms);
    }
    return 0;
}

// Self destruction

static void self_dtr_cb(struct timer_list *timer)
{
    struct my_entry *entry = container_of(timer, struct my_entry, timer);
    // unsigned long flags;

    MOD_INFO("Self destruction of '%s'", entry->name);

    // use spinlock, because we in softirq context
    spin_lock(&queue_lock);
    if (list_empty(&entry->list))
        MOD_INFO("self_dtr: entry is already deleted");
    else
        list_del(&entry->list);

    spin_unlock(&queue_lock);

    if (use_refcnt)
        kref_put(&entry->refcnt, release_entry);
    else
        free_entry(entry);
}

static int self_dtr_insert(const char *name)
{
    struct my_entry *entry = __make_entry(name);
    ulong delay;
    unsigned long flags;

    if (IS_ERR(entry))
        return PTR_ERR(entry);

    if (sscanf(entry->name, "%lu", &delay) != 1) {
        MOD_WARN("Timer time is not specified");
        delay = dins_ms;
    }

    if (use_refcnt)
        kref_get(&entry->refcnt);  // <<<<<

    timer_setup(&entry->timer, self_dtr_cb, 0);
    mod_timer(&entry->timer, jiffies + msecs_to_jiffies(delay));  // Not delay, time in the future

    // use irqsave, because timer interrupt can preemt syscall context
    spin_lock_irqsave(&queue_lock, flags);
    list_add_tail(&entry->list, &my_queue);
    spin_unlock_irqrestore(&queue_lock, flags);

    return 0;
}

// External work

struct __ext_work_struct {
    struct my_entry *entry;
    uint delay;
    struct work_struct work;
};

static void __do_external_work(struct work_struct *work)
{
    struct __ext_work_struct *ework = container_of(work, struct __ext_work_struct, work);
    struct my_entry *e = ework->entry;

    MOD_INFO("Starting work at entry %p for %u", e, ework->delay);
    atomic_set(&e->state, ENTRY_UNDDER_WORK);
    msleep(ework->delay);
    atomic_set(&e->state,ENTRY_END_WORK);
    complete_all(&e->work_end);
    MOD_INFO("Work for %p has ended", e);

    kfree(ework);
    kref_put(&e->refcnt, release_entry);
}

static int work_with_entry(const char *name)
{
    struct my_entry *entry = __make_entry(name);
    ulong delay;
    struct __ext_work_struct *ework;

    if (IS_ERR(entry))
        return PTR_ERR(entry);

    ework = kzalloc(sizeof(*ework), GFP_KERNEL);
    if (!ework) {
        free_entry(entry);
        return -ENOMEM;
    }

    if (sscanf(entry->name, "%lu", &delay) != 1) {
        MOD_WARN("Delayed cmd does not contain time");
        delay = dins_ms;
    }

    kref_get(&entry->refcnt);  // <<<<<<
    spin_lock(&queue_lock);
    list_add_tail(&entry->list, &my_queue);
    spin_unlock(&queue_lock);

    ework->entry = entry;
    ework->delay = delay;
    INIT_WORK(&ework->work, __do_external_work);
    queue_work(wq, &ework->work);

    return 0;
}

// Sysfs

static enum oper parse_cmd(const char *buf, size_t count, char *str)
{
    struct __str_to_oper *cur = str_to_op;
    enum oper op = UNKNOWN;
    while(cur->name) {
        MOD_DEBUG("Comparing '%s' and '%s' %ld", cur->name, buf, cur->len);
        if (!strncmp(cur->name, buf, cur->len - 1)) {
            op = cur->op;
            buf += cur->len;
            count -= cur->len;
            break;
        }
        cur++;
    }

    if (op != UNKNOWN)
        strncpy(str, buf, MIN(count, MAX_ENTRY_NAME - 1));

    return op;
}

static ssize_t work_store(struct kobject *kobj,
                          struct kobj_attribute *attr, const char *buf,
                          size_t count)
{
    // Do some operations
    char name[MAX_ENTRY_NAME] = { 0 };
    enum oper op = parse_cmd(buf, count, name);
    int err = 0;

    switch (op) {
        case INSERT:
            err = insert_to_queue(name);
            break;
        case DELAYED_INSERT:
            err = delayed_insert(name);
            break;
        case SPAWN_MULTI:
            err = spawn_multi(name);
            break;
        case RUN_THREAD:
            wake_up_process(bg_thread);
            break;
        case SELF_DTR:
            err = self_dtr_insert(name);
            break;
        case EXT_WORK:
            err = work_with_entry(name);
            break;
        case UNKNOWN:
            MOD_ERR("Unknown operation '%s'", buf);
            err = -EINVAL;
            break;
    }
    return err ? err : count;
}

static ssize_t work_show(struct kobject *kobj,
                         struct kobj_attribute *attr, char *buf)
{
    // Show list
    ssize_t ret = 0, count = 0;
    struct list_head *pos;

    ret += sysfs_emit_at(buf, ret, "Queue:\n");
    spin_lock(&queue_lock);

    list_for_each(pos, &my_queue) {
        struct my_entry *e = container_of(pos, struct my_entry, list);
        ret += sysfs_emit_at(buf, ret, "%lu. %s\n", ++count, e->name);
    }

    spin_unlock(&queue_lock);

    return ret;
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

    wq = alloc_workqueue("queue_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, MAX_WQ_WORKS);
    if (!wq) {
        err = -ENOMEM;
        goto init_err;
    }

    bg_thread = kthread_create(bg_work, NULL, "queue_bg_work");
    if (IS_ERR(bg_thread)) {
        err = PTR_ERR(bg_thread);
        MOD_ERR("Failed to created thread, err %d", err);
        goto dtr_wq;
    }

    entry_cache = kmem_cache_create("entry_cache", sizeof(struct my_entry), NULL, SLAB_HWCACHE_ALIGN);
    if (!entry_cache) {
        MOD_ERR("Failed to created mem cache");
        err = -EINVAL;
        goto dtr_thread;
    }

    if ((err = sysfs_create_file(&THIS_MODULE->mkobj.kobj, &work_entry_attr.attr))) {
        MOD_ERR("Can't create pid file in sysfs, err %d", err);
        goto dtr_cache;
    }
    MOD_INFO("Module loaded");
    return 0;
dtr_cache:
    kmem_cache_destroy(entry_cache);
dtr_thread:
    kthread_stop(bg_thread);
dtr_wq:
    destroy_workqueue(wq);
init_err:
    return err;
}

static void __exit hello_exit(void)
{
    sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &work_entry_attr.attr);
    kthread_stop(bg_thread);
    clean_queue();
    flush_workqueue(wq);
    destroy_workqueue(wq);
    kmem_cache_destroy(entry_cache);
    MOD_INFO("Module unloaded");
}

// Module params

module_param(dins_ms, ulong, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(dins_ms, "Delay for work insertion");

module_param(thread_sleep_ms, ulong, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(thread_sleep_ms, "Sleep time for background thread");

module_param(thread_active_sleep, bool, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(thread_active_sleep, "True: uses mdelay to wait");

module_param(use_refcnt, bool, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(use_refcnt, "Use reference counts");

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");