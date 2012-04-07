/**
 * sysdlp.c
 *
 * Monitors file-related system calls.
 *
 * Uses the drmgr extension for thread-context-local data that is preserved
 * properly across Windows callbacks.
 */

#include "dr_api.h"
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include "syscallhijack.h"

using namespace std;

# define __DEBUG
# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
# define ATOMIC_INC(var) __asm__ __volatile__("lock incl %0" : "=m" (var) : : "memory")

static void event_exit(void);
static bool event_filter_syscall(void *drcontext, int sysnum);
static bool event_pre_syscall(void *drcontext, int sysnum);
static void event_post_syscall(void *drcontext, int sysnum);
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating);
static void event_thread_context_init(void *drcontext, bool new_depth);
static void event_thread_context_exit(void *drcontext, bool process_exit);

DR_EXPORT void 
dr_init(client_id_t id)
{
    drmgr_init();
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    dr_register_post_syscall_event(event_post_syscall);
    dr_register_exit_event(event_exit);
    //dr_register_bb_event(event_basic_block);

    tlsIdx = drmgr_register_cls_field(event_thread_context_init, event_thread_context_exit);
}

DR_EXPORT void 
event_thread_context_init(void *drcontext, bool new_depth)
{
    if (new_depth) 
    {
	SThreadData *pData = (SThreadData *) dr_thread_alloc(drcontext, sizeof(SThreadData));
	pData->m_rgArgs = NULL;
	pData->m_iFileType = FILE_TYPE_NORMAL;
	pData->m_logger.Initialize(LOGGER_FILE);
	drmgr_set_cls_field(drcontext, tlsIdx, pData);
    }
}

DR_EXPORT void 
event_thread_context_exit(void *drcontext, bool process_exit)
{
    if (process_exit) 
    {
	SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
	dr_thread_free(drcontext, pData, sizeof(SThreadData));
    }
}

DR_EXPORT void 
event_exit(void)
{
    dr_fprintf(STDERR, "Tainted locations:\n");
    if (shblk == NULL)
	goto dr_uninit;

    for (uint16_t hi=0; hi<0xffff; ++hi)
    {
        if (!shblk[hi]) continue;
        
        for (uint16_t lo=0; lo<0xffff; ++lo)
        {
            if (shblk[hi][lo])
                dr_fprintf(STDERR, "0x%04x%04x, ", hi, lo);
        }
    }

 dr_uninit:
    drmgr_unregister_cls_field(event_thread_context_init,
			       event_thread_context_exit,
			       tlsIdx);
    drmgr_exit();
}

DR_EXPORT bool
event_filter_syscall(void *drcontext, int sysnum)
{
    switch (sysnum)
    {
    case SYS_open:
    case SYS_read:
    case SYS_write:
    case SYS_close:
        return true;
    }
    
    return false;
}

DR_EXPORT bool
event_pre_syscall(void *drcontext, int sysnum)
{
    switch(sysnum)
    {
    case SYS_open:
	return event_pre_open(drcontext);
    case SYS_close:
	return event_pre_close(drcontext);
    case SYS_read:
	return event_pre_read(drcontext);
    case SYS_write:
	return event_pre_write(drcontext);
    }
    
    return true;    
}

DR_EXPORT void
event_post_syscall(void *drcontext, int sysnum)
{
    switch(sysnum)
    {
    case SYS_open:
	event_post_open(drcontext);
	return;
    case SYS_read:
	event_post_read(drcontext);
	return;
    }
}

DR_EXPORT dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
    return DR_EMIT_DEFAULT;
}
