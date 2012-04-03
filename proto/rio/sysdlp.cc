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

using namespace std;

# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
# define ATOMIC_INC(var) __asm__ __volatile__("lock incl %0" : "=m" (var) : : "memory")

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

DR_EXPORT void 
dr_init(client_id_t id)
{
    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event(event_pre_syscall);
    dr_register_post_syscall_event(event_post_syscall);
    dr_register_exit_event(event_exit);
    dr_register_bb_event(event_basic_block);
    
    memset(shblk, 0, 0xffff * sizeof(uint8_t*));
}

static void 
event_exit(void)
{
    dr_fprintf(STDERR, "Tainted locations:\n");
    for (uint16_t hi=0; hi<0xffff; ++hi)
    {
        if (!shblk[hi]) continue;
        
        //dr_fprintf(STDERR, "0x%04x____\n", hi);
        for (uint16_t lo=0; lo<0xffff; ++lo)
        {
            if (shblk[hi][lo])
                dr_fprintf(STDERR, "0x%04x%04x\n", hi, lo);
        }
    }
}

static bool
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
    return (sFileName.find("/media/") != string::npos);
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
            uint32_t addr = (uint32_t) buf + i;
            uint16_t hi   = (addr >> 16) & 0xffff;
            uint16_t lo   = (addr & 0xffff);
            
            if (!shblk[hi]) /* shadow block has not been allocated */
            {
                shblk[hi] = (uint8_t*) malloc(0xffff * sizeof(uint8_t));
                memset(shblk[hi], 0, 0xffff * sizeof(uint8_t));
            }
                
            uint8_t* shadow_ptr = &((shblk[hi])[lo]);
            *shadow_ptr = 1;
        }
    }
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (sysnum == SYS_open)
    {
        const char* szFileName = (const char*) dr_syscall_get_param(drcontext, 0);
        int flags = (int) dr_syscall_get_param(drcontext, 1);
        bool bWrite = (flags & O_WRONLY) | (flags & O_RDWR);
        
        return on_open(szFileName, bWrite);
    }
    
    return true;    
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    if (sysnum == SYS_read)
    {
        int fd = (int) dr_syscall_get_param(drcontext, 0);
        void* buf = (void*) dr_syscall_get_param(drcontext, 1);
        size_t count = (size_t) dr_syscall_get_param(drcontext, 2);
        ssize_t bytes_read = (ssize_t) dr_syscall_get_result(drcontext);
        
        post_read(fd, buf, count, bytes_read);
    }
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
    return DR_EMIT_DEFAULT;
}
