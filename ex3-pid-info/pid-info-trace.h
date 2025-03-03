#undef TRACE_SYSTEM
#define TRACE_SYSTEM example

#if !defined(EXAMPLE_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define EXAMPLE_TRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(pid_info_task_iter,
    TP_PROTO(struct task_struct *t, pid_t spid),
    TP_ARGS(t, spid),
    TP_STRUCT__entry(
        __field(pid_t, search_pid)
        __field(pid_t, cur_pid)
        __array(char, name, TASK_COMM_LEN)
        __field(uint, state)
    ),
    TP_fast_assign(
        __entry->search_pid = spid;
        __entry->cur_pid = t->pid;
        memcpy(__entry->name, t->comm, TASK_COMM_LEN);
        __entry->state = t->__state;
    ),
    TP_printk("search=%d {pid=%d, name=%s, state=%s}", __entry->search_pid,
              __entry->cur_pid, __entry->name,
              __entry->state ? __print_flags(__entry->state, "|", 
                { 1, "S"} , { 2, "D" }, { 4, "T" }, { 8, "t" }
              ) : "R")
);

#endif // EXAMPLE_TRACE_H

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE pid-info-trace

#include <trace/define_trace.h>
