#pragma once

#define __DEBUG

#include <string>
#include <stdint.h>
#include <set>
#include <map>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include "dr_api.h"
#include "drmgr.h"
#include "util.h"
#include "persistence.h"

// List of all open files
static std::map<int, std::string> openFiles;
// List of tainted files loaded in the process; any buffers loaded from these files will be marked tainted
static std::set<int> taintedFiles;
// List of external files loaded in the process; tainted buffers should not be written to these
// This will not work when programs use SYS_rename instead of SYS_write
static std::set<int> externalFiles;
// The taint store
static TaintStore store;

static bool
is_external(const std::string& sFileName)
{
    // TODO: To be extended to include network
    return (sFileName.find("/media/") != std::string::npos);
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
    openFiles.insert(std::pair<int, std::string>(fid, (const char *) pData->m_rgArgs[0]));
    
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
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_pre_mmap] ERR: Thread local storage is not set up\n");
	return true;
    }
    
    pData->m_rgArgs = NULL;

    // Between open and close, this call can allocate memory to play with.
    reg_t fid = dr_syscall_get_param(drcontext, 4);
    reg_t flags = dr_syscall_get_param(drcontext, 3);
    if (fid == (int) -1 && flags == MAP_ANONYMOUS | MAP_PRIVATE)
    {
	// Text editors like EMACS use buffers instead of actual files. The user updates
	// the buffer which is then written back to a temp file and that is then renamed 
	// to the user's file. This is a smart concept that allows for multiple buffers for
	// each file. But, it turns out to be a PITA for us.
	// Ideally, we should use instruction level hooking here (see the PIN version).
	// But since we are trying our hand at sys call hooking, this is our logic:
	// if the mmap-ed buffer is ANON and fid is -1, the buffer is tainted.
	// We cannot be sure when the buffer gets created, so we can't wait for the OPEN call.
	// The downside is that these programs become always-tainted programs if any changes are made.
	// Possible improvement: program specific policies that tell us when tainted buffers get loaded.
	
	pData->m_rgArgs = (reg_t *) dr_thread_alloc(drcontext, 1 * sizeof(reg_t));
	memset(pData->m_rgArgs, 0, 1 * sizeof(reg_t));
	pData->m_rgArgs[0] = dr_syscall_get_param(drcontext, 1); // length

	return true;
    }

    if (taintedFiles.find(fid) == taintedFiles.end())
    {
	// Technically, to be safe, we should mark any fid associated with a mmap buffer as 
	// tainted on the sys call level if not hooking at instruction level.
	// But we won't do that. It will taint everything in the system.
	return true;
    }

    dr_fprintf(STDERR, "Creating an mmap of fid = %d\n", fid);
    return true;
}

static bool event_post_mmap(void *drcontext)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_post_mmap] ERR: Thread local storage is not set up\n");
	return true;
    }

    if (pData->m_rgArgs == NULL)
    {
	// Nothing to do; not tainted
	return true;
    }

    void *buf = (void *) dr_syscall_get_result(drcontext);
    if (buf == MAP_FAILED)
    {
	dr_thread_free(drcontext, pData->m_rgArgs, sizeof(reg_t) * 1);
	pData->m_rgArgs = NULL;
	return true;
    }

    size_t length = (size_t) pData->m_rgArgs[0];
    
    set_tainted_buf(buf, length);

    dr_thread_free(drcontext, pData->m_rgArgs, sizeof(reg_t) * 1);
    pData->m_rgArgs = NULL;
    return true;
}

static bool event_pre_munmap(void *drcontext)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_pre_munmap] ERR: Thread local storage is not set up\n");
	return true;
    }

    reg_t addr = dr_syscall_get_param(drcontext, 0);
    reg_t length = dr_syscall_get_param(drcontext, 1);

    // We don't care if the munmap succeeds or not. Just clear the taint.
    reset_tainted_buf((void *) addr, (size_t) length);

    return true;
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

    dr_fprintf(STDERR, "[DLP][event_post_read] Going to set tainted buf; buf = %p, length = %d\n", 
	       buf, bytesRead);
    set_tainted_buf(buf, bytesRead);

    // clear the pData's args
    dr_thread_free(drcontext, pData->m_rgArgs, sizeof(reg_t) * 3);
    pData->m_rgArgs = NULL;

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
    dr_fprintf(STDERR, "[DLP][event_pre_write] Going to add tainted file; name = %s\n", mapIter->second.c_str());
    store.AddTainted(mapIter->second.c_str());
    
    return true;
}

static bool event_pre_sendmsg(void *drcontext)
{
    reg_t sockfd = dr_syscall_get_param(drcontext, 0);
    reg_t msg = dr_syscall_get_param(drcontext, 1);
    reg_t flags = dr_syscall_get_param(drcontext, 2);

    if ((const struct msghdr *) msg == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_pre_sendmsg] msg is empty; sockfd = %d\n", (int) sockfd);
	return true;
    }

    dr_fprintf(STDERR, "In event_pre_sendmsg\n");
    const struct msghdr *sMsg = (struct msghdr *) msg;
    size_t msg_iovlen = sMsg->msg_iovlen;
    if (msg_iovlen == 0)
	return true;

    struct iovec *msg_iov = sMsg->msg_iov;
    for (int i = 0; i < msg_iovlen; i++)
    {
	struct iovec *curr = msg_iov + i;
	if (is_tainted_buf(curr->iov_base, curr->iov_len))
	{
	    dr_fprintf(STDERR, "[DLP][send_msg] Found a taint\n");
	    return true;
	}

	dr_fprintf(STDERR, "[DLP][send_msg] Not found a taint\n");
    }

    return true;
}

static bool event_pre_writev(void *drcontext)
{
    reg_t fd = dr_syscall_get_param(drcontext, 0);
    reg_t iov = dr_syscall_get_param(drcontext, 1);
    reg_t iov_cnt = dr_syscall_get_param(drcontext, 2);
    
    if ((int) iov_cnt == 0)
	return false;

    dr_fprintf(STDERR, "[DLP][event_pre_writev] fd = %d, iov_cnt = %d\n", (int)fd, iov_cnt);
    for (int i = 0; i < (int) iov_cnt; i++)
    {
	struct iovec *curr = (struct iovec *) curr + i;
	if ((int) curr->iov_len <= 0 || curr->iov_base == NULL)
	    continue;
	
	dr_fprintf(STDERR, "[DLP][event_pre_writev] curr->iov_len = %d, curr->iov_base=%p\n", 
		   curr->iov_len, curr->iov_base);
	if (is_tainted_buf(curr->iov_base, 1))
	{
	    dr_fprintf(STDERR, "[DLP][event_pre_writev] Found a taint; fd = %d\n", (int) fd);
	    return true;
	}

	//dr_fprintf(STDERR, "[DLP][event_pre_writev] Not found a taint; fd = %d\n", (int) fd);
    }

    return true;
}

static bool event_pre_rename(void *drcontext)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_pre_rename] ERR: Thread local storage is not set up\n");
	return true;
    }

    reg_t oldFile = dr_syscall_get_param(drcontext, 0);
    reg_t newFile = dr_syscall_get_param(drcontext, 1);
    if (is_external((const char *) newFile))
    {
	char buffer[500];
	sprintf(buffer, "[DLP] Trying to write sensitive data to external location; filename = %s\n",
		(const char *) newFile);
	write_log(drcontext, buffer);
	return false;
    }

    if (!store.CheckTainted((const char *) oldFile))
	return true;

    pData->m_rgArgs = (reg_t *) dr_thread_alloc(drcontext, 2 * sizeof(reg_t));
    pData->m_rgArgs[0] = oldFile;
    pData->m_rgArgs[1] = newFile;

    return true;
}

static bool event_post_rename(void *drcontext)
{
    SThreadData *pData = (SThreadData *) drmgr_get_cls_field(drcontext, tlsIdx);
    if (pData == NULL)
    {
	dr_fprintf(STDERR, "[DLP][event_post_rename] ERR: Thread local storage is not set up\n");
	return true;
    }

    if (pData->m_rgArgs == NULL)
    {
	return true;
    }

    dr_fprintf(STDERR, "[DLP][event_post_rename] Removing %s; Adding %s\n", 
	       (const char *) pData->m_rgArgs[0],
	       (const char *) pData->m_rgArgs[1]);
    store.RemoveTainted((const char *) pData->m_rgArgs[0]);
    store.AddTainted((const char *) pData->m_rgArgs[1]);
    
    dr_thread_free(drcontext, pData->m_rgArgs, 2 * sizeof(reg_t));
    pData->m_rgArgs = NULL;

    return true;
}
