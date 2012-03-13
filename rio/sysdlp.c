/**
 * sysdlp.c
 *
 * Monitors file-related system calls.
 *
 * Uses the drmgr extension for thread-context-local data that is preserved
 * properly across Windows callbacks.
 */

#include "dr_api.h"
#include "drmgr.h"
#include <string.h>
#include <syscall.h>

# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
# define ATOMIC_INC(var) __asm__ __volatile__("lock incl %0" : "=m" (var) : : "memory")

# define SYS_MAX_ARGS 3

/* Thread-context-local data structure for storing system call
 * parameters.  Since this state spans application system call
 * execution, thread-local data is not sufficient on Windows: we need
 * thread-context-local, or "callback-local", provided by the drmgr
 * extension.
 */
typedef struct {
    reg_t param[SYS_MAX_ARGS];
    bool repeat;
} per_thread_t;

/* Thread-context-local storage index from drmgr */
static int tcls_idx;

/* The system call number of SYS_write/NtWriteFile */
static int open_sysnum;

static int num_syscalls;

static int get_open_sysnum(void);
static void event_exit(void);
static void event_thread_context_init(void *drcontext, bool new_depth);
static void event_thread_context_exit(void *drcontext, bool process_exit);
static bool event_filter_syscall(void *drcontext, int sysnum);
static bool event_pre_syscall(void *drcontext, int sysnum);
static void event_post_syscall(void *drcontext, int sysnum);

DR_EXPORT void 
dr_init(client_id_t id)
{
    drmgr_init();
    open_sysnum = get_open_sysnum();
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    dr_register_post_syscall_event(event_post_syscall);
    dr_register_exit_event(event_exit);
    tcls_idx = drmgr_register_cls_field(event_thread_context_init,
                                        event_thread_context_exit);
    DR_ASSERT(tcls_idx != -1);
#ifdef SHOW_RESULTS
    if (dr_is_notify_on()) {
        dr_fprintf(STDERR, "DLP is monitoring system calls\n");
    }
#endif
}

static void 
show_results(void)
{
#ifdef SHOW_RESULTS
    char msg[512];
    int len;
    /* Note that using %f with dr_printf or dr_fprintf on Windows will print
     * garbage as they use ntdll._vsnprintf, so we must use dr_snprintf.
     */
    len = dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]),
                      "<Number of system calls seen: %d>", num_syscalls);
    DR_ASSERT(len > 0);
    msg[sizeof(msg)/sizeof(msg[0])-1] = '\0';
    DISPLAY_STRING(msg);
#endif /* SHOW_RESULTS */
}

static void 
event_exit(void)
{
    show_results();
    drmgr_unregister_cls_field(event_thread_context_init,
                               event_thread_context_exit,
                               tcls_idx);
    drmgr_exit();
}

static void
event_thread_context_init(void *drcontext, bool new_depth)
{
    /* create an instance of our data structure for this thread context */
    per_thread_t *data;
#ifdef SHOW_RESULTS
    dr_fprintf(STDERR, "new thread context id=%d%s\n", dr_get_thread_id(drcontext),
               new_depth ? " new depth" : "");
#endif
    if (new_depth) {
        data = (per_thread_t *) dr_thread_alloc(drcontext, sizeof(per_thread_t));
        drmgr_set_cls_field(drcontext, tcls_idx, data);
    } else
        data = (per_thread_t *) drmgr_get_cls_field(drcontext, tcls_idx);
    memset(data, 0, sizeof(*data));
}

static void 
event_thread_context_exit(void *drcontext, bool thread_exit)
{
#ifdef SHOW_RESULTS
    dr_fprintf(STDERR, "resuming prior thread context id=%d\n",
               dr_get_thread_id(drcontext));
#endif
    if (thread_exit) {
        per_thread_t *data = (per_thread_t *) drmgr_get_cls_field(drcontext, tcls_idx);
        dr_thread_free(drcontext, data, sizeof(per_thread_t));
    }
    /* else, nothing to do: we leave the struct for re-use on next context */
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return (sysnum == open_sysnum);
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    ATOMIC_INC(num_syscalls);
    
    if (sysnum == open_sysnum)
    {
#ifdef SHOW_RESULTS
    dr_fprintf(STDERR, "open(\"%s\", 0x%x, 0x%x)",
               dr_syscall_get_param(drcontext, 0),
               dr_syscall_get_param(drcontext, 1),
               dr_syscall_get_param(drcontext, 2));
#endif
    }
    
    return true; /* execute normally */
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    if (sysnum == open_sysnum)
    {
#ifdef SHOW_RESULTS
    dr_fprintf(STDERR, " = 0x%x\n",
               (ptr_int_t)dr_syscall_get_result(drcontext));
#endif
    }
}

static int
get_open_sysnum(void)
{
    return SYS_open;
}
