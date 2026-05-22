#define MOD_PRFX "livecode: "
#define pr_fmt(fmt) MOD_PRFX fmt "\n"

#include "linux/spinlock.h"
#include "linux/mutex.h"
#include "linux/spinlock_types.h"
#include "linux/kref.h"
#include "linux/completion.h"
#include "linux/preempt.h"
#include "linux/jiffies.h"
#include "linux/workqueue.h"
#include "linux/workqueue_types.h"
#include "linux/sched.h"
#include "linux/kthread.h"
#include "linux/delay.h"
#include "linux/types.h"
#include "linux/container_of.h"
#include "linux/list.h"
#include "linux/gfp_types.h"
#include "linux/slab.h"
#include "linux/array_size.h"
#include "linux/kobject.h"
#include "linux/printk.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>

// ==== commands ====

enum command {
    PRINT,
    ALLOC,
    FREE,
    ADD_LIST,
    DEL_LIST,
    ATOM,
    KTHREAD,
    KTHREAD_STOP,
    WORK,
    TIMER,
    COMPLETION,
    REFCNT,
    LOCK,
    UNKNOWN,
};

static int do_print(char *args);
static int do_mem(char *args);
static int do_free(char *args);
static int do_add_list(char *args);
static int do_del_list(char *args);
static int do_atom(char *args);
static int do_kthread(char *args);
static int do_kthread_stop(char *args);
static int do_workq(char *args);
static int do_timer(char *args);
static int do_completion(char *args);
static int do_refcnt(char *args);
static int do_lock(char *args);

typedef int (*cmd_func_t)(char *args);

#define __STR_TO_command(name, op, f) { name, sizeof(name) - 1, op, f }
#define STR_TO_command(name, op, f) __STR_TO_command(name ": ", op, f)

static struct {
    const char *name;
    size_t len;
    enum command op;
    cmd_func_t func;
} str_to_op[] = {
    STR_TO_command("print", PRINT, do_print),
    STR_TO_command("alloc", ALLOC, do_mem),
    STR_TO_command("free", FREE, do_free),
    STR_TO_command("add", ADD_LIST, do_add_list),
    STR_TO_command("del", DEL_LIST, do_del_list),
    STR_TO_command("atom", ATOM, do_atom),
    STR_TO_command("kthread", KTHREAD, do_kthread),
    STR_TO_command("stop_kt", KTHREAD_STOP, do_kthread_stop),
    STR_TO_command("workq", WORK, do_workq),
    STR_TO_command("timer", TIMER, do_timer),
    STR_TO_command("compl", COMPLETION, do_completion),
    STR_TO_command("kref", REFCNT, do_refcnt),
    STR_TO_command("lock", LOCK, do_lock),
};

#define MAX_ENTRY_NAME (64)

// ==== LIVE CODE ====

struct my_obj {
    u64 data;
    struct kobject kobj;
    struct list_head head;
};

static int *mem;
struct kmem_cache *kcache;
static struct my_obj *my_obj;

static LIST_HEAD(main);

static atomic_t atom = ATOMIC_INIT(10);
static volatile ulong flags;

static int do_print(char *args)
{
    pr_info("print command");
    pr_info("arguments are %s", args);
    if (mem) {
        pr_info("Mem value is %d", *mem);
        for (int i = 0; i < 10; i++) {
            pr_info("Mem[%d] value is %d", i, mem[i]);
        }
    } else {
        pr_warn("Mem is null");
    }
    if (my_obj) {
        pr_info("Obj data is %llu", my_obj->data);
    } else {
        pr_warn("Obj is null");
    }
    return 0;
}

static int do_mem(char *args)
{
    int err = 0;
    u64 x;
    // mem = kzalloc(sizeof(int) * 100, GFP_KERNEL);
    // mem = kmalloc_array(100, sizeof(int), GFP_KERNEL);
    // kmem_cache_alloc(kcache, GFP_KERNEL);
    // // 1M > -> vmalloc
    // for (int i = 0; i < 10; i++) {
    //     mem[i] = i * i;
    // }
    err = kstrtou64(args, 16, &x);
    // err = sscanf(args, "%llx", &x);
    if (err) {
        pr_err("String %s is not a number", args);
        return -EINVAL;
    }
    my_obj = kmem_cache_alloc(kcache, GFP_KERNEL);
    my_obj->data = x;
    pr_info("addr is %px", my_obj);
    // *mem = 200;
    return err;
}

static int do_free(char *args)
{
    kfree(mem);
    mem = NULL;
    kmem_cache_free(kcache, my_obj);
    my_obj = NULL;
    return 0;
}

static int do_add_list(char *args)
{
    int err = 0;
    u64 x;
    err = kstrtou64(args, 16, &x);
    if (err) {
        pr_err("String %s is not a number", args);
        return -EINVAL;
    }
    my_obj = kmem_cache_alloc(kcache, GFP_KERNEL);
    my_obj->data = x;
    INIT_LIST_HEAD(&my_obj->head);
    list_add(&my_obj->head, &main);
    return err;
}

static int do_atom(char *args)
{
    int err = 0;
    u64 x;
    err = kstrtou64(args, 16, &x);
    if (err) {
        pr_err("String %s is not a number", args);
        return -EINVAL;
    }
    pr_info("Atom=%d", atomic_read(&atom));
    atomic_set(&atom, x);
    // pr_info("Atom=%d", atomic_read(&atom));
    // atomic_add(x, &atom);
    // pr_info("Atom=%d", atomic_read(&atom));
    // y = atomic_fetch_add(x, &atom);
    // pr_info("Atom=%d y=%d", atomic_read(&atom), y);
    // y = atomic_cmpxchg(&atom, 3 * x, 17);
    // pr_info("Atom=%d y=%d", atomic_read(&atom), y);
    // y = atomic_cmpxchg(&atom, 3 * x, 17);
    // pr_info("Atom=%d y=%d", atomic_read(&atom), y);
    // pr_info("Flags=%lx", flags);
    // set_bit(12, &flags);
    // pr_info("Flags=%lx", flags);
    // set_bit(1, &flags);
    // pr_info("Flags=%lx", flags);
    // if (test_bit(x, &flags)) {
    //     pr_info("Flag %llx is enabled", x);
    // } else {
    //     pr_warn("Flag %llx is disabled", x);
    // }

    if (!test_and_set_bit(x, &flags)) {
        pr_info("Flag %llx is enabled", x);
    } else {
        pr_info("Flag %llx is already enabled, do nothing", x);
    }
    return err;
}

static int do_del_list(char *args)
{
    struct my_obj *e, *tmp;
    list_for_each_entry_safe(e, tmp, &main, head) {
        list_del(&e->head);
        kmem_cache_free(kcache, e);
        break;
    }
    return 0;
}

/*
 * =====================================
 * ==== 1. Kthread + msleep + delay ====
 * =====================================
 */

// BP1: task_struct
static struct task_struct *th_struct;
struct thread_data {
    int cpu;
    ulong magic;
    uint time_ms;
    bool should_delay;
};

static int kthread_example(void *data)
{
    struct thread_data *d = data;
    // BP2: should_stop
    while (!kthread_should_stop()) {
        pr_info("Kthread on cpu %d (desired %d), magic %lx", current->on_cpu,
                d->cpu, d->magic);
        if (d->should_delay) {
            mdelay(d->time_ms);
            // BP3: Try to remove cond_resched :)
            cond_resched();
        } else {
            msleep(d->time_ms);
        }
    }
    pr_info("Kthread (magic %lx) ended", d->magic);
    kfree(d);
    return 0;
}

static int do_kthread(char *args)
{
    int err = 0;
    struct thread_data *d = NULL;
    int x;
    ulong magic, time_ms;
    int is_delay;

    err = sscanf(args, "%d %lu %lu %d", &x, &magic, &time_ms, &is_delay);
    if (err != 4) {
        pr_err("Failed to read cpu and magic from '%s'", args);
        pr_err("Expected <cpu> <magic> <sleep_time> <is_delay>");
        err = -EINVAL;
        goto exit;
    } else {
        err = 0;
    }

    d = kmalloc(sizeof(*d), GFP_KERNEL);
    *d = (struct thread_data){
        .cpu = x,
        .magic = magic,
        .time_ms = time_ms,
        .should_delay = !!is_delay,
    };
    th_struct = kthread_create_on_cpu(kthread_example, (void *)d, x,
                                      "lv-exam-kt:%u");
    // BP4: ptr-err conversion
    if (IS_ERR(th_struct)) {
        err = PTR_ERR(th_struct);
        th_struct = NULL;
        pr_err("Failed to create thread, err=%d", err);
        goto exit;
    }

    // BP5: should manually start process
    wake_up_process(th_struct);

    // BP6: kthread_run
    // th_struct = kthread_run_on_cpu(kthread_example, (void*)d, x, "lv-exam-kt:%u");
exit:
    return err;
}

static int do_kthread_stop(char *args)
{
    if (!th_struct) {
        pr_err("Thread is not running");
        return -EPERM;
    }

    // BP6: stop the thread
    kthread_stop(th_struct);
    return 0;
}

/*
 * ================================
 * ==== 2. Workqueue + delayed ====
 * ================================
 */

struct work_data {
    int cpu;
    ulong magic;
    struct work_struct work;
    struct delayed_work dwork;
};

static struct workqueue_struct *wq;

static void __process_work(struct work_data *d)
{
    int cpu = current->on_cpu;
    ulong m = d->magic;
    pr_info("Work is processed: cpu=%d magic=%lx comm=%16s", cpu, m,
            current->comm);
    kfree(d);
}

static void __handle_work(struct work_struct *work)
{
    struct work_data *d = container_of(work, struct work_data, work);
    __process_work(d);
}

static void __handle_dwork(struct work_struct *dwork)
{
    struct work_data *d = container_of(dwork, struct work_data, dwork.work);
    __process_work(d);
}

static int do_workq(char *args)
{
    int err = 0;
    struct work_data *d = NULL;
    int x;
    ulong magic, time_ms;

    if (!wq) {
        wq = alloc_workqueue("lv-wq-ex", WQ_MEM_RECLAIM, 3);
        if (!wq) {
            pr_err("Failed to create workqueue");
            return -EINVAL;
        }
    }

    err = sscanf(args, "%d %lu %lu", &x, &magic, &time_ms);
    if (err != 3) {
        pr_err("Failed to read cpu and magic from '%s'", args);
        pr_err("Expected <cpu> <magic> <sleep_time>");
        err = -EINVAL;
        goto exit;
    } else {
        err = 0;
    }

    d = kmalloc(sizeof(*d), GFP_KERNEL);
    *d = (struct work_data){
        .cpu = x,
        .magic = magic,
    };

    if (time_ms) {
        INIT_DELAYED_WORK(&d->dwork, __handle_dwork);
        queue_delayed_work_on(x, wq, &d->dwork, msecs_to_jiffies(time_ms));
    } else {
        INIT_WORK(&d->work, __handle_work);
        // queue_work_on(x, wq, &d->work);
        queue_work(wq, &d->work);
    }

    pr_info("Work is queued, magic=%lx", magic);
exit:
    return err;
}

/*
 * ==============================
 * ======== 3. Timers ===========
 * ==============================
 */

struct timer_data {
    ulong magic;
    struct timer_list timer;
};

__maybe_unused static DEFINE_SPINLOCK(slock);
static void __timer_cb(struct timer_list *timer)
{
    struct timer_data *d = container_of(timer, struct timer_data, timer);
    bool in_int = in_interrupt();
    pr_info("Timer cb is caled, magic=%lx int=%d", d->magic, in_int);
    spin_lock(&slock);
    pr_info("Test under lock");
    spin_unlock(&slock);
    kfree(d);
}

static int do_timer(char *args)
{
    int err;
    ulong magic, time_ms;
    struct timer_data *d = NULL;

    err = sscanf(args, "%lu %lu", &magic, &time_ms);
    if (err != 2) {
        pr_err("Failed to magic from '%s'", args);
        pr_err("Expected <magic> <sleep_time>");
        err = -EINVAL;
        goto exit;
    } else {
        err = 0;
    }

    d = kmalloc(sizeof(*d), GFP_KERNEL);
    *d = (struct timer_data){
        .magic = magic,
    };
    timer_setup(&d->timer, __timer_cb, 0);
    mod_timer(&d->timer, jiffies + msecs_to_jiffies(time_ms));
    pr_info("Timer is ready, magic=%lx", magic);
exit:
    return err;
}

/*
 * ==============================
 * ======= 4. Completion ========
 * ==============================
 */

// BP1: completion should be initialized
struct completion cmpl;

static int do_completion(char *args)
{
    int err = 0;
    int val;

    err = kstrtoint(args, 10, &val);
    if (err) {
        pr_err("Failed to parse '%s' to int", args);
        goto exit;
    }

    if (val < -2) {
        pr_err("Unknown value %d", val);
    } else if (val == -2) {
        reinit_completion(&cmpl);
        pr_info("Reinit of completion");
    } else if (val == -1) {
        pr_info("Waiting for completion (%d)...", current->pid);
        // BP2: wait_for_completion* family
        wait_for_completion(&cmpl);
        pr_info("Completion done (%d)", current->pid);
    } else if (val == 0) {
        pr_info("Complete all");
        complete_all(&cmpl);
    } else {
        pr_info("Complete for one waiter");
        complete(&cmpl);
    }

exit:
    return err;
}

/*
 * ==============================
 * ========= 5. Refcnt ==========
 * ==============================
 */

struct kref_data {
    ulong magic;
    struct kref kref;
};

static struct kref_data *kref_ex = NULL;

static void __dtr_kref_data(struct kref *kref)
{
    struct kref_data *d = container_of(kref, struct kref_data, kref);
    pr_info("Destroy kref_data, magic=%lx", d->magic);
    kfree(d);
    kref_ex = NULL;
}

static int do_refcnt(char *args)
{
    int err = 0;
    int val;

    err = kstrtoint(args, 10, &val);
    if (err) {
        pr_err("Failed to parse '%s' to int", args);
        goto exit;
    }

    if (val >= 0) {
        if (kref_ex) {
            kref_get(&kref_ex->kref);
            pr_info("Inc kref, result=%d", kref_read(&kref_ex->kref));
        } else {
            kref_ex = kmalloc(sizeof(*kref_ex), GFP_KERNEL);
            kref_ex->magic = current->pid;
            kref_init(&kref_ex->kref);
            pr_info("Created kref_data");
        }
    } else {
        if (kref_ex) {
            if (!kref_put(&kref_ex->kref, __dtr_kref_data)) {
                pr_info("Dec kref, result=%d", kref_read(&kref_ex->kref));
            }
        } else {
            pr_info("Kref_data is empty");
        }
    }

    // init
    // ....
    // kref_init -> 1
    // "publish"

    // lock
    // kref_get +1
    // unlock
    // process
    // kref_put

    // dtr
    // lock
    // "unpublish"
    // unlock
    // kref_put === 1 - 1 = 0 -> call_dtr

exit:
    return err;
}

/*
 * =============================
 * ========= 6. Locks ==========
 * =============================
 */

__maybe_unused static DEFINE_MUTEX(mlock);

static int do_lock(char *args)
{
    int err = 0;

    // spin_lock_init(&slock);
    // mutex_init(&mlock);
    return err;
}
// ====================
// ====================
// ====================

// ======= Sysfs ======

static enum command parse_cmd(const char *buf, size_t count, char *str,
                              cmd_func_t *func)
{
    enum command op = UNKNOWN;
    for (uint i = 0; i < ARRAY_SIZE(str_to_op); i++) {
        pr_debug("Comparing '%s' and '%s' (%ld)", str_to_op[i].name, buf,
                 str_to_op[i].len);
        if (!strncmp(str_to_op[i].name, buf, str_to_op[i].len - 1)) {
            op = str_to_op[i].op;
            *func = str_to_op[i].func;
            buf += str_to_op[i].len;
            count -= str_to_op[i].len;
            break;
        }
    }

    if (op != UNKNOWN)
        strncpy(str, buf, MIN(count, MAX_ENTRY_NAME - 1));

    return op;
}

static ssize_t _sysfs_store(struct kobject *kobj, struct kobj_attribute *attr,
                            const char *buf, size_t count)
{
    char name[MAX_ENTRY_NAME] = { 0 };
    cmd_func_t func = NULL;
    enum command op = parse_cmd(buf, count, name, &func);
    int err = 0;

    if (op == UNKNOWN) {
        pr_err("Got unknown command: %s", buf);
        return -EINVAL;
    }

    if (!func) {
        pr_err("Command %d doesn't have function", op);
        return -EPERM;
    }

    err = func(name);

    return err ? err : count;
}

static ssize_t _sysfs_show(struct kobject *kobj, struct kobj_attribute *attr,
                           char *buf)
{
    ssize_t ret = 0;
    struct list_head *e;

    list_for_each(e, &main) {
        struct my_obj *obj = container_of(e, struct my_obj, head);
        pr_info("Working with %px", obj);
        ret += sysfs_emit_at(buf, ret, "List data is %llu\n", obj->data);
    }

    return ret;
}

static const struct kobj_attribute control_entry_attr = {
    .attr = {
        .name = "control",
        .mode = S_IRUGO | S_IWUGO,
    },
    .show = _sysfs_show,
    .store = _sysfs_store,
};

static ssize_t _test_show(struct kobject *kobj, struct kobj_attribute *attr,
                          char *buf)
{
    ssize_t ret = 0;

    ret += sysfs_emit(buf, "Test world\n");

    return ret;
}

static const struct kobj_attribute test_entry_attr = {
    .attr = {
        .name = "my_obj",
        .mode = S_IRUGO | S_IWUGO,
    },
    .show = _test_show,
};

static struct kobject *obj;

static int __init hello_init(void)
{
    int err;
    if ((err = sysfs_create_file(&THIS_MODULE->mkobj.kobj,
                                 &control_entry_attr.attr))) {
        pr_err("Can't create file in sysfs, err %d", err);
        goto err;
    }

    kcache = kmem_cache_create("kmem", sizeof(struct my_obj), NULL, 0);

    obj = kobject_create_and_add("test", &THIS_MODULE->mkobj.kobj);
    err = sysfs_create_file(obj, &test_entry_attr.attr);
    init_completion(&cmpl);

    pr_info("Module loaded");
    return 0;

err:
    return err;
}

static void __exit hello_exit(void)
{
    sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &control_entry_attr.attr);
    sysfs_remove_file(obj, &test_entry_attr.attr);
    kobject_del(obj);
    kmem_cache_destroy(kcache);
    if (th_struct)
        kthread_stop(th_struct);
    if (wq)
        destroy_workqueue(wq);
    pr_info("Module unloaded");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
