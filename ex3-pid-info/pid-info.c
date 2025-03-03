#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <stdio.h>

// Macros for logging
#define EX3_PRFX "example3: "
#define EX3_DEBUG(fmt, ...) pr_debug(EX3_PRFX fmt "\n", ##__VA_ARGS__)
#define EX3_INFO(fmt, ...) pr_info(EX3_PRFX fmt "\n", ##__VA_ARGS__)
#define EX3_WARN(fmt, ...) pr_warn(EX3_PRFX fmt "\n", ##__VA_ARGS__)
#define EX3_ERR(fmt, ...) pr_err(EX3_PRFX fmt "\n", ##__VA_ARGS__)

#define CREATE_TRACE_POINTS
#include "pid-info-trace.h"

struct search_task {
    char name[TASK_COMM_LEN];
    pid_t pid;
    pid_t tgid;
    pid_t ppid;

    int cpu;
    int prior;
	int sprior;
	int nprior;
	uint rtprior;

    uint state;

    bool found;
};



enum search_types {
    SEARCH_BY_PID = 0,
    SEARCH_BY_NAME = 1,
};

static ssize_t print_task(struct search_task *info, char *buf)
{
    ssize_t ret = 0;
    if (info->found) {
        ret += sysfs_emit_at(buf, ret, "Task:\n");
        ret += sysfs_emit_at(buf, ret, "    name=%16s\n", info->name);
        ret += sysfs_emit_at(buf, ret, "    pid=%d tgid=%d ppid=%d\n",
                             info->pid, info->tgid, info->ppid);
        ret += sysfs_emit_at(buf, ret, "    prior=%d sprior=%d nprior=%d rtprior=%u\n",
                             info->prior, info->sprior, info->nprior, info->rtprior);
        ret += sysfs_emit_at(buf, ret, "    cpu=%d state=0x%x\n", info->cpu, info->state);
    } else {
        ret += sysfs_emit(buf, "Pid %d not found\n", info->pid);
    }
    return ret;
}

// Function to find task_struct by pid/name
static void search_task(struct search_task *info, enum search_types stype)
{
    struct task_struct *leader, *cur_task;

    trace_printk("My tracepoint at search_task info{ %d, %16s }\n", info->pid, info->name);
    rcu_read_lock();

    for_each_process_thread(leader, cur_task) {
        task_lock(cur_task);

        EX3_DEBUG("Processing task %d [%16s]", cur_task->pid, cur_task->comm);
        trace_pid_info_task_iter(cur_task, info->pid);
        if ((stype == SEARCH_BY_PID && cur_task->pid == info->pid) ||
            (stype == SEARCH_BY_NAME && strnstr(cur_task->comm, info->name, TASK_COMM_LEN))) {
            info->found = true;
            memcpy(info->name, cur_task->comm, TASK_COMM_LEN);
            info->pid = cur_task->pid;
            info->tgid = cur_task->tgid;
            info->ppid = cur_task->parent->pid;
            info->cpu = cur_task->on_cpu;
            info->prior = cur_task->prio;
            info->sprior = cur_task->static_prio;
            info->nprior = cur_task->normal_prio;
            info->rtprior = cur_task->rt_priority;
            info->state = cur_task->__state;
        }

        task_unlock(cur_task);

        if (info->found)
            goto found;

    }

found:
    rcu_read_unlock();
}

// sysfs functions

static struct kobject *example_kobject;
static struct search_task pid_search, name_search;

// Search by pid
static ssize_t pid_search_show(struct kobject *kobj,
                               struct kobj_attribute *attr, char *buf)
{
    return print_task(&pid_search, buf);
}

static ssize_t pid_search_store(struct kobject *kobj,
                                struct kobj_attribute *attr, const char *buf,
                                size_t count)
{
    if (kstrtoint(buf, 10, &pid_search.pid)) {
        pid_search.pid = -1;
        pid_search.found = false;
        EX3_DEBUG("Bad pid %s", buf);
        return -EINVAL;
    }

    pid_search.found = false;
    search_task(&pid_search, SEARCH_BY_PID);
    return count;
}

static const struct kobj_attribute pid_search_attr = {
    .attr = {
        .name = "pid",
        .mode = S_IRUGO | S_IWUGO,
    },
    .show = pid_search_show,
    .store = pid_search_store,
};

// Search by name

static ssize_t name_search_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
    return print_task(&name_search, buf);
}

static ssize_t name_search_store(struct kobject *kobj,
                                 struct kobj_attribute *attr, const char *buf,
                                 size_t count)
{
    size_t len = strlen(buf) - 1;  // -1 for \n

    if (len > TASK_COMM_LEN) {
        EX3_WARN("Too long name, len is %lu", len);
        len = TASK_COMM_LEN;
    }

    memcpy(name_search.name, buf, len);

    name_search.found = false;
    search_task(&name_search, SEARCH_BY_NAME);
    return count;
}

static const struct kobj_attribute name_search_attr = {
    .attr = {
        .name = "name",
        .mode = S_IRUGO | S_IWUGO,
    },
    .show = name_search_show,
    .store = name_search_store,
};

static int __init hello_init(void)
{
    int err = 0;

    EX3_DEBUG("Hello, my first DEBUG");
    EX3_WARN("Hello, my first WARN");
    EX3_ERR("Hello, my first ERR");

    example_kobject = kobject_create_and_add("search", &THIS_MODULE->mkobj.kobj);

    if (!example_kobject) {
        EX3_ERR("Can't create kobject");
        return -ENOMEM;
    }

    if ((err = sysfs_create_file(example_kobject, &pid_search_attr.attr))) {
        EX3_ERR("Can't create pid file in sysfs, err %d", err);
        goto init_err;
    }

    if ((err = sysfs_create_file(example_kobject, &name_search_attr.attr))) {
        EX3_ERR("Can't create name file in sysfs, err %d", err);
        goto init_err;
    }

    EX3_INFO("Module loaded");
    return 0;

init_err:
    sysfs_remove_file(example_kobject, &pid_search_attr.attr);
    sysfs_remove_file(example_kobject, &name_search_attr.attr);
    kobject_put(example_kobject);
    example_kobject = NULL;
    return err;
}

static void __exit hello_exit(void)
{
    if (example_kobject) {
        sysfs_remove_file(example_kobject, &pid_search_attr.attr);
        sysfs_remove_file(example_kobject, &name_search_attr.attr);
        kobject_put(example_kobject);  
    }
    EX3_INFO("Module unloaded");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
