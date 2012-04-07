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
#include <set>
#include <map>
#include "logger.h"
#include "persistence.h"

using namespace std;
//aa
# define __DEBUG
# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
# define ATOMIC_INC(var) __asm__ __volatile__("lock incl %0" : "=m" (var) : : "memory")
# define FILE_TYPE_NORMAL   0
# define FILE_TYPE_TAINTED  1
# define FILE_TYPE_EXTERNAL 2
struct SThreadData
{
    Logger m_logger;
    int m_iFileType;
    reg_t* m_rgArgs;

    SThreadData()
	: m_iFileType(FILE_TYPE_NORMAL)
	, m_rgArgs(NULL)
    {
	//m_logger.Initialize(LOGGER_FILE);
    }
};

// The index for thread local storage
static int tlsIdx;
// List of all open files
static std::map<int, std::string> openFiles;
// List of tainted files loaded in the process; any buffers loaded from these files will be marked tainted
static std::set<int> taintedFiles;
// List of external files loaded in the process; tainted buffers should not be written to these
// This will not work when programs use SYS_rename instead of SYS_write
static std::set<int> externalFiles;
/* Shadow memory (32-bit) */
/* 64K blocks of 64KB each. shblk[] contain the pointer to the real blocks. */
/* Note that the block pointers consume (64 * 4 = 256) KB */
static uint8_t** shblk = NULL;
static TaintStore store;

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

// Get the pointer to the flags block in the 2-D array
inline static uint8_t* get_shadow_ptr(uint32_t addr)
{
    // Lazy allocation; probably not of any use for tainted programs.
    // However, will save something for programs that don't load tainted files.
    if (shblk == NULL)
    {
	shblk = (uint8_t **) dr_global_alloc(0xffff * sizeof(uint8_t*));
	memset(shblk, 0, 0xffff * sizeof(uint8_t*));
    }

    uint16_t ho_idx = (uint16_t) ((addr >> 16) & 0xffff);
    uint8_t* lo_blk = shblk[ho_idx];
    if (lo_blk == NULL)
    {
	lo_blk = (uint8_t *) dr_global_alloc(0xffff * sizeof(uint8_t));
	memset(lo_blk, 0, 0xffff * sizeof(uint8_t));
	shblk[ho_idx] = lo_blk;
    }
    
    uint16_t lo_idx = (uint16_t) addr;
    return &(lo_blk[lo_idx]);
}

inline static bool is_tainted_buf(void *buf, size_t size)
{
    void *ptr = buf;
    for (int i = 0; i < size; i++, ptr = ptr + 1)
    {	
	uint32_t addr = (uint32_t) ptr;
	uint8_t *pFlags = get_shadow_ptr(addr);
	if (*pFlags == 1)
	    return true;
    }

    return false;
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
    
    //memset(shblk, 0, 0xffff * sizeof(uint8_t*));
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

static bool
is_external(const string& sFileName)
{
    // TODO: To be extended to include network
    return (sFileName.find("/media/") != string::npos);
}

static bool is_confidential(const char* szFileName)
{
    return (store.CheckTainted(szFileName));
}

static bool event_pre_open(void *drcontext)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_pre_open] ERR: Thread local storage is not set up\n");
	return true;
    }

    reg_t fileArg = dr_syscall_get_param(drcontext, 0);
    pData->m_rgArgs = (reg_t *) dr_thread_alloc(drcontext, 1 * sizeof(reg_t));
    pData->m_rgArgs[0] = fileArg;

    const char *szFileName = (const char*) fileArg;
    if (is_confidential(szFileName))
    {
	pData->m_iFileType = FILE_TYPE_TAINTED;
	
	char buffer[500];
	sprintf(buffer, "[DLP] Confidential file about to be opened: %s\n", szFileName);
	write_log(pData, buffer);

	return true;
    }

    if (is_external(szFileName))
    {
	pData->m_iFileType = FILE_TYPE_EXTERNAL;
    
	char buffer[500];
	sprintf(buffer, "[DLP] External file about to be opened: %s\n", szFileName);
	write_log(pData, buffer);
	
	return true;
    }

    pData->m_iFileType = FILE_TYPE_NORMAL;
    
    return true;
}

static bool event_pre_close(void *drcontext)
{
    int fid = (int) dr_syscall_get_param(drcontext, 0);
    // TODO: We assume the file will close; is a flawed assumption; will consider moving this to post_call
    openFiles.erase(fid);

    std::set<int>::iterator iter = taintedFiles.find(fid);
    if (iter != taintedFiles.end())
    {
	taintedFiles.erase(iter);
#ifdef __DEBUG
	dr_fprintf(STDERR, "[DLP][event_pre_close] DEBUG: Closing tainted fid = %d\n", fid);
#endif
	return true;
    }

    iter = externalFiles.find(fid);
    if (iter != externalFiles.end())
    {
	externalFiles.erase(iter);
#ifdef __DEBUG
	dr_fprintf(STDERR, "[DLP][event_pre_close] DEBUG: Closing external fid = %d\n", fid);
#endif
	return true;
    }
    
    return true;
}

static bool event_pre_mmap(void *drcontext)
{
    // Between open and close, this call can allocate memory to play with.
    // But do we need to really do anything here; probably not
}

static bool event_pre_read(void *drcontext)
{
    reg_t fid = dr_syscall_get_param(drcontext, 0);
    if (taintedFiles.find((int) fid) == taintedFiles.end())
	return true;

    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_pre_read] ERR: Thread local storage is not set up\n");
	return true;
    }

    // Array of three; add to TLS to get sent to the post event
    pData->m_rgArgs = (reg_t *) dr_thread_alloc(drcontext, 3 * sizeof(reg_t));
    pData->m_rgArgs[0] = fid;
    pData->m_rgArgs[1] = dr_syscall_get_param(drcontext, 1);
    pData->m_rgArgs[2] = dr_syscall_get_param(drcontext, 2);

    return true;
}

static bool event_pre_write(void *drcontext)
{
    reg_t fid = dr_syscall_get_param(drcontext, 0);
    // If the file is already tainted, just proceed
    if (taintedFiles.find((int) fid) != taintedFiles.end())
	return true;

    // Check if the fid is in the open files list
    std::map<int, std::string>::iterator mapIter = openFiles.find((int) fid);
    if (mapIter == openFiles.end())
    {
	dr_fprintf(STDERR, "[DLP][event_pre_write] ERR: This is unnatural; writing to a file that was never opened; fid = %d\n", fid);
	return true;
    }

    // Check if there is tainted buf
    reg_t buf = dr_syscall_get_param(drcontext, 1);
    reg_t size = dr_syscall_get_param(drcontext, 2);
    if (!is_tainted_buf((void *) buf, (size_t) size))
    {
	// Nothing to do; just return
	return true;
    }

    // If the file is external and trying to write tainted buffer, block
    if (externalFiles.find((int) fid) != externalFiles.end())
    {
	char buffer[500];
	sprintf(buffer, "[DLP] Trying to write sensitive data to external location; filename = %s\n",
		mapIter->second.c_str());
	write_log(drcontext, buffer);
	 
	// Block write
	return false;
    }

    // Add the file to the tainted list
    store.AddTainted(mapIter->second.c_str());
    
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

    int fid = (int) dr_syscall_get_result(drcontext);
    if (fid == -1)
	return true;

    // Regardless of file type, add to openFiles map
    openFiles.insert(pair<int, std::string>(fid, (const char *) pData->m_rgArgs[0]));
    
    dr_thread_free(drcontext, pData->m_rgArgs, 1 * sizeof(reg_t));
    pData->m_rgArgs = NULL;

    if (pData->m_iFileType == FILE_TYPE_NORMAL)
	return true;

    int iFileType = pData->m_iFileType;
    pData->m_iFileType = FILE_TYPE_NORMAL;
    
    if (iFileType == FILE_TYPE_TAINTED)
    {
	taintedFiles.insert(fid);
#ifdef __DEBUG
	dr_fprintf(STDERR, "[DLP][event_post_open] DEBUG: Added file to tainted list; fid = %d\n", fid);
#endif
	return true;
    }

    if (iFileType == FILE_TYPE_EXTERNAL)
    {
	externalFiles.insert(fid);
#ifdef __DEBUG
	dr_fprintf(STDERR, "[DLP][event_post_open] DEBUG: Added file to external list; fid = %d\n", fid);
#endif
	return true;
    }

    return true;
}

static bool event_post_read(void *drcontext)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_post_read] ERR: Thread local storage is not set up\n");
	return true;
    }

    if (pData->m_rgArgs == NULL)
    {
	// Nothing to do; not tainted
	return true;
    }

    ssize_t bytesRead = (ssize_t) dr_syscall_get_result(drcontext);
    void *buf = (void *) pData->m_rgArgs[1];
    for (int i = 0; i < bytesRead; i++)
    {
	// Set to shadow table
	uint32_t addr = (uint32_t) (buf + i);
	uint8_t* pFlags = get_shadow_ptr(addr);
	*pFlags = 1;
    }

    // clear the pData's args
    dr_thread_free(drcontext, pData->m_rgArgs, sizeof(reg_t) * 3);
    pData->m_rgArgs = NULL;

    return true;
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
