#pragma once

#include <string.h>
#include <stdint.h>
#include "dr_api.h"
#include "drmgr.h"

#define LOGGER_FILE "/home/vivek/Desktop/audit/dlp.log"

class Logger
{
private:
    file_t m_file;
  
public:
    Logger()
	: m_file(INVALID_FILE) 
    {
  
    }

    ~Logger() 
    {
	if (m_file != INVALID_FILE) 
	{
	    dr_close_file(m_file);
	    m_file = INVALID_FILE;
	}
    }

    bool Initialize() 
    {
	return Initialize(LOGGER_FILE);
    }

    bool Initialize(const char *szFilename) 
    {
	m_file = dr_open_file(szFilename, DR_FILE_WRITE_APPEND);
	if (m_file == INVALID_FILE)
	{
	    dr_fprintf(STDERR, "File could not be opened");
	    return false;
	}
	
	return true;
    }
	
    void WriteLog(const char *szLog) 
    {
	if (m_file == INVALID_FILE)
	{
	    dr_fprintf(STDERR, "No file; %s", szLog);
	    return;
	}
	//dr_fprintf(STDERR, "No file; %s", szLog);
	ssize_t numWritten = dr_write_file(m_file, szLog, strlen(szLog) + 1);
	return;
    }
};
