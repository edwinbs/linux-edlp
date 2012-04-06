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
#include <string>
#include <stdint.h>
#include <vector>
#include "logger.h"

using namespace std;
//aa
# define __DEBUG
# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
# define ATOMIC_INC(var) __asm__ __volatile__("lock incl %0" : "=m" (var) : : "memory")

struct SThreadData
{
  Logger m_logger;
  bool m_bTainted;

  SThreadData()
    : m_bTainted(false) {
    m_logger.Initialize(LOGGER_FILE);
  }
};

// The index for thread local storage
static int tlsIdx;
// List of tainted files loaded in the process; any buffers loaded from these files will be marked tainted
static std::vector<int> taintedFiles;
/* Shadow memory (32-bit) */
/* 64K blocks of 64KB each. shblk[] contain the pointer to the real blocks. */
/* Note that the block pointers consume (64 * 4 = 256) KB */
static uint8_t* shblk[0xffff];

/* Shadow of IA32 General Purpose Registers */
static uint8_t shgpr[8];

static bool is_tainted;

static void event_exit(void);
static bool event_filter_syscall(void *drcontext, int sysnum);
static bool event_pre_syscall(void *drcontext, int sysnum);
static void event_post_syscall(void *drcontext, int sysnum);
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating);
static void event_thread_context_init(void *drcontext, bool new_depth);
static void event_thread_context_exit(void *drcontext, bool process_exit);

inline static void write_log(SThreadData *pData, const char *szLog)
{
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][write_log] Could not load the thread data; log = %s", szLog);
	return;
    }
    
    //dr_fprintf(STDERR, "[DLP] %s\n", szLog);
    pData->m_logger.WriteLog(szLog);
}

inline static void write_log(void *drcontext, const char *szLog)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    write_log(pData, szLog);
}

inline static uint8_t* get_shadow_ptr(uint32_t addr)
{
    uint8_t** shadow_pp = &shblk[(addr >> 16) & 0xffff];
    
    if (!(*shadow_pp)) /* shadow block has not been allocated */
    {
        *shadow_pp = (uint8_t*) malloc(0xffff * sizeof(uint8_t));
        memset(*shadow_pp, 0, 0xffff * sizeof(uint8_t));
    }
        
    return &((*shadow_pp)[(addr & 0xffff)]);
}

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
    
    memset(shblk, 0, 0xffff * sizeof(uint8_t*));
}

DR_EXPORT void 
event_thread_context_init(void *drcontext, bool new_depth)
{
    if (new_depth) 
    {
	SThreadData *pData = (SThreadData *) dr_thread_alloc(drcontext, sizeof(SThreadData));
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
    for (uint16_t hi=0; hi<0xffff; ++hi)
    {
        if (!shblk[hi]) continue;
        
        for (uint16_t lo=0; lo<0xffff; ++lo)
        {
            if (shblk[hi][lo])
                dr_fprintf(STDERR, "0x%04x%04x\n", hi, lo);
        }
    }

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

static bool
is_external(const string& sFileName)
{
    // TODO: To be extended to include network
    return (sFileName.find("/media/") != string::npos);
}

static bool is_confidential(const string& sFileName)
{
    // TODO: To be extended to make this customizable
    return (sFileName.find("confidential") != string::npos);
}

static bool
on_open(const string& sFileName, bool bWrite)
{
    if (is_tainted && bWrite && is_external(sFileName))
    {
        dr_fprintf(STDERR, "[DLP] BLOCKED write: %s\n", sFileName.c_str());
        return false;
    }

    if (sFileName.find("confidential") != string::npos)
    {
        is_tainted = true;
    }
        
    return true;
}

static void
post_read(int fd, void* buf, size_t count, ssize_t bytes_read)
{
    if (is_tainted)
    {
        printf("Tainted load % 4d bytes to 0x%08x\n",
            bytes_read, (uint32_t) buf);
            
        for (ssize_t i = 0; i < bytes_read; ++i)
        {       
            uint8_t* shadow_ptr = get_shadow_ptr((uint32_t) buf + i);
            *shadow_ptr = 1;
        }
    }
}

static bool event_pre_open(void *drcontext)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_pre_open] ERR: Thread local storage is not set up\n");
	return true;
    }

    const char *szFileName = (const char*) dr_syscall_get_param(drcontext, 0);
    //write_log(pData, szFileName);
    if (!is_confidential(szFileName))
    {
	pData->m_bTainted = false;
	return true;
    }

    pData->m_bTainted = true;
    
    char buffer[200];
    sprintf(buffer, "[DLP] Confidential file about to be opened: %s", szFileName);
    write_log(pData, buffer);

    return true;
}

static bool event_post_open(void *drcontext)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_post_open] ERR: Thread local storage is not set up\n");
	return true;
    }

    if (!pData->m_bTainted)
	return true;

    pData->m_bTainted = false;
    
    int fid = (int) dr_syscall_get_result(drcontext);
    if (fid == -1)
	return true;

    taintedFiles.push_back(fid);
#ifdef __DEBUG
    dr_fprintf(STDERR, "[DLP][event_post_open] DEBUG: Added file to tainted list; fid = %d\n", fid);
#endif
    return true;
}

DR_EXPORT bool
event_pre_syscall(void *drcontext, int sysnum)
{
    switch(sysnum)
    {
    case SYS_open:
	return event_pre_open(drcontext);
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
    }
}

DR_EXPORT dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
    return DR_EMIT_DEFAULT;
}
