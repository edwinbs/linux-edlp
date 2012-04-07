#pragma once

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <set>
#include "dr_api.h"
#include "drmgr.h"

#define TAINT_FILE "/home/vivek/Desktop/dlp/taint_store.db"
#define MAX_FILE 1024

class TaintStore
{
private:
    file_t m_taintFile;
    std::set<std::string> m_fileNames;
    void *m_fileNamesMutex;
    
    void Uninitialize()
    {
	if (m_taintFile != INVALID_FILE)
	{
	    dr_close_file(m_taintFile);
	    m_taintFile = INVALID_FILE;
	}
    }

    void Initialize(const char *szFileName)
    {
	Uninitialize();
	
	m_taintFile = dr_open_file(szFileName, DR_FILE_WRITE_APPEND);
	if (m_taintFile == INVALID_FILE)
	{
	    dr_fprintf(STDERR, "[DLP][TaintStore::Initialize] ERR: File %s could not be opened\n", szFileName);
	    return;
	}
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

	dr_rwlock_write_unlock(m_fileNamesMutex);
    }

public:
    TaintStore()
	: m_taintFile(INVALID_FILE)
    {
	Initialize(TAINT_FILE);
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
	bool result = (m_fileNames.find(szFileName) != m_fileNames.end());
	dr_rwlock_read_unlock(m_fileNamesMutex);

	return result;
    }

    void RefreshStore()
    {
	LoadData();
    }

    void AddTainted(const char *szFileName)
    {
	if (CheckTainted(szFileName))
	    return;

	int len = strlen(szFileName);
	if (len > MAX_FILE - 1)
	{
	    dr_fprintf(STDERR, "File name too long; name = %s, max allowed = %d", szFileName, (MAX_FILE - 1));
	    return;
	}
	
	char buff[MAX_FILE];
	sprintf(buff, "%s\n", szFileName);

	dr_rwlock_write_lock(m_fileNamesMutex);
	dr_file_seek(m_taintFile, 0, DR_SEEK_END);
	dr_write_file(m_taintFile, buff, len + 1);
	dr_rwlock_write_unlock(m_fileNamesMutex);

	LoadData();
    }

    void RemoveTainted(const char *szFileName)
    {
	// TODO: Implement
    }
};
