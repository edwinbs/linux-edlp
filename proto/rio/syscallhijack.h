#pragma once

#include <string>
#include <stdint.h>
#include <set>
#include <map>

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


