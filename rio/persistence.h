#pragma once

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <set>
#include "dr_api.h"
#include "drmgr.h"
#include "config.h"

#define MAX_FILE 1024

class TaintStore
{
private:
    file_t m_taintFile;
    file_t m_wlFile;
    std::set<std::string> m_fileNames;
    std::set<std::string> m_softTaint;
    std::set<std::string> m_whitelist;
    void *m_fileNamesMutex;
    
    void Uninitialize()
    {
	if (m_taintFile != INVALID_FILE)
	{
	    dr_close_file(m_taintFile);
	    m_taintFile = INVALID_FILE;
	}

	if (m_wlFile != INVALID_FILE)
	{
	    dr_close_file(m_wlFile);
	    m_wlFile = INVALID_FILE;
	}
    }

    void Initialize(const char *szFileName, const char *szWLFile)
    {
	Uninitialize();
	
	m_taintFile = dr_open_file(szFileName, DR_FILE_WRITE_APPEND);
	if (m_taintFile == INVALID_FILE)
	{
	    dr_fprintf(STDERR, "[DLP][TaintStore::Initialize] ERR: File %s could not be opened\n", szFileName);
	    return;
	}

	m_wlFile = dr_open_file(szWLFile, DR_FILE_READ);
	if (m_wlFile == INVALID_FILE)
	{
	    dr_fprintf(STDERR, "[DLP][TaintStore::Initialize] ERR: File %s could not be opened\n", szWLFile);
	    return;
	}
    }

    void LoadWhiteList()
    {
	if (m_wlFile == INVALID_FILE)
	{
	    dr_fprintf(STDERR, "[DLP][LoadWhiteList] ERR: Whitelist file has not been initialized\n");
	    return;
	}

	m_whitelist.clear();
	if (!dr_file_seek(m_wlFile, 0, DR_SEEK_END))
	{
	    dr_fprintf(STDERR, "dr_file_seek to end failed\n");
	    return;
	}
	
	int64 iEnd = dr_file_tell(m_wlFile);
	if (iEnd <= 0)
	{
	    return;
	}

	dr_file_seek(m_wlFile, 0, DR_SEEK_SET);
	
	void *buf = dr_global_alloc(iEnd);
	if (!buf)
	{
	    dr_fprintf(STDERR, "The buffer could not be allocated; size = %d", iEnd);
	    return;
	}

	ssize_t cbBytes = dr_read_file(m_wlFile, buf, iEnd);
	if (cbBytes == 0)
	{
	    dr_global_free(buf, iEnd);
	    dr_fprintf(STDERR, "No bytes read from the whitelist file\n");
	    return;
	}
	
	void *ptr = buf;
	for (int i = 0; i < iEnd;)
	{
	    char *fileName = (char*) dr_global_alloc(MAX_FILE);
	    memset(fileName, 0, MAX_FILE);
	    sscanf((const char*) ptr, "%s\n", fileName);
	    std::string sFileName = fileName;
	    m_whitelist.insert(sFileName);
	    
	    dr_global_free(fileName, MAX_FILE);
	    int offset = sFileName.size() + 1;
	    ptr = ptr + offset;
	    i = i + offset;
	    dr_fprintf(STDERR, "[DLP] DEBUG: Loaded %s\n", sFileName.c_str());
	}

	if (buf)
	    dr_global_free(buf, iEnd);
	
	return;
    }

    void LoadData()
    {
	if (m_taintFile == INVALID_FILE)
	{
	    dr_fprintf(STDERR, "[DLP][LoadData] ERR: Taint file has not been initialized\n");
	    return;
	}
	
	if (!dr_rwlock_write_trylock(m_fileNamesMutex))
	{
	    dr_fprintf(STDERR, "[DLP][LoadData] ERR: Could not acquire write lock to refresh the tainted store\n");
	    return;
	}

	m_fileNames.clear();

	if (!dr_file_seek(m_taintFile, 0, DR_SEEK_END))
	{
	    dr_fprintf(STDERR, "dr_file_seek to end failed\n");
	    dr_rwlock_write_unlock(m_fileNamesMutex);
	    return;
	}
	
	int64 iEnd = dr_file_tell(m_taintFile);
	if (iEnd <= 0)
	{
	    //dr_fprintf(STDERR, "The taint file is empty\n");
	    dr_rwlock_write_unlock(m_fileNamesMutex);
	    return;
	}

	dr_file_seek(m_taintFile, 0, DR_SEEK_SET);
	
	void *buf = dr_global_alloc(iEnd);
	if (!buf)
	{
	    dr_fprintf(STDERR, "The buffer could not be allocated; size = %d", iEnd);
	    dr_rwlock_write_unlock(m_fileNamesMutex);
	    return;
	}

	ssize_t cbBytes = dr_read_file(m_taintFile, buf, iEnd);
	if (cbBytes == 0)
	{
	    dr_global_free(buf, iEnd);
	    dr_fprintf(STDERR, "No bytes read from the taint file\n");
	    dr_rwlock_write_unlock(m_fileNamesMutex);
	    return;
	}
	
	void *ptr = buf;
	for (int i = 0; i < iEnd;)
	{
	    char *fileName = (char*) dr_global_alloc(MAX_FILE);
	    memset(fileName, 0, MAX_FILE);
	    sscanf((const char*) ptr, "%s\n", fileName);
	    std::string sFileName = fileName;
	    m_fileNames.insert(sFileName);
	    
	    dr_global_free(fileName, MAX_FILE);
	    int offset = sFileName.size() + 1;
	    ptr = ptr + offset;
	    i = i + offset;
	    //dr_fprintf(STDERR, "[DLP] DEBUG: Loaded %s\n", sFileName.c_str());
	}

	if (buf)
	    dr_global_free(buf, iEnd);

	LoadWhiteList();

	dr_rwlock_write_unlock(m_fileNamesMutex);
    }

public:
    TaintStore()
	: m_taintFile(INVALID_FILE)
    {
	Initialize(TAINT_FILE, WHITELIST);
	m_fileNamesMutex = dr_rwlock_create();
	LoadData();
    }

    ~TaintStore()
    {
	dr_rwlock_destroy(m_fileNamesMutex);
	Uninitialize();
    }

    bool CheckTainted(const char *szFileName)
    {
	if (szFileName == NULL)
	    return false;

	dr_rwlock_read_lock(m_fileNamesMutex);
	bool result = (
	    (m_fileNames.find(szFileName) != m_fileNames.end()) || 
	    (m_softTaint.find(szFileName) != m_softTaint.end()));
	dr_rwlock_read_unlock(m_fileNamesMutex);

	return result;
    }

    int CheckWhitelist(const char *szFileName)
    {
	if (szFileName == NULL)
	    return 0;
    
	dr_rwlock_read_lock(m_fileNamesMutex);
	int result = (m_whitelist.find(szFileName) != m_whitelist.end()) ? 1 : 0;
	if (!result)
	{
	    std::string sFilename = szFileName;
	    std::set<std::string>::iterator iter = m_whitelist.begin();
	    for (; iter != m_whitelist.end(); iter++)
	    {
		if (sFilename.find(iter->c_str()) != std::string::npos)
		{
		    result = 2;
		    break;
		}
	    }
	}

	dr_rwlock_read_unlock(m_fileNamesMutex);

	return result;
    }

    void RefreshStore()
    {
	LoadData();
    }

    bool AddTainted(const char *szFileName)
    {
	if (CheckTainted(szFileName))
	    return false;

	int result = CheckWhitelist(szFileName);
	if (result != 0)
	{
	    m_softTaint.insert(szFileName);
	    return true;
	}

	int len = strlen(szFileName);
	if (len > MAX_FILE - 1)
	{
	    dr_fprintf(STDERR, "File name too long; name = %s, max allowed = %d", szFileName, (MAX_FILE - 1));
	    return false;
	}
	
	char buff[MAX_FILE];
	sprintf(buff, "%s\n", szFileName);

	dr_rwlock_write_lock(m_fileNamesMutex);
	dr_file_seek(m_taintFile, 0, DR_SEEK_END);
	dr_write_file(m_taintFile, buff, len + 1);
	dr_rwlock_write_unlock(m_fileNamesMutex);

	LoadData();

	return true;
    }

    bool RemoveTainted(const char *szFileName)
    {
	m_softTaint.erase(szFileName);
	return true;
    }
};
