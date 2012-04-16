#pragma once

#include "logger.h"
#include "memory.h"

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
