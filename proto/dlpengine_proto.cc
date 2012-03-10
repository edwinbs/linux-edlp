#include "dlpengine_proto.h"

#include <stdio.h>
#include <dlfcn.h> 
#include <sstream>

typedef FILE* (*pf_fopen_t)(const char *path, const char *mode);
typedef int (*pf_fprintf_t)(FILE* stream, const char * format, ... );
typedef int (*pf_fclose_t)(FILE* stream);

using namespace std;

namespace
{
    static pf_fopen_t sys_fopen = (pf_fopen_t) dlsym(RTLD_NEXT, "fopen");
    static pf_fprintf_t sys_fprintf = (pf_fprintf_t) dlsym(RTLD_NEXT, "fprintf");
    static pf_fclose_t sys_fclose = (pf_fclose_t) dlsym(RTLD_NEXT, "fclose");
    
    inline void LogImpl(const char* szText)
    {
        FILE* pFile = sys_fopen("~/Desktop/dlp_proto.log", "a");
        
        if (pFile)
        {
            sys_fprintf(pFile, szText);
            sys_fclose(pFile);
            pFile = NULL;
        }
    }
    
};

#define LOG(x)                          \
    stringstream stream;                \
    stream << __FUNCTION__ << ", ";     \
    stream << x << endl;                \
    LogImpl(stream.str().c_str());      \

CDLPEngineProto::CDLPEngineProto()
    :   m_bDirty(false)
{ }

bool CDLPEngineProto::OnOpen(const std::string& sFileName, bool bWrite)
{
    LOG("File name=" << sFileName.c_str() << ", write=" << (bWrite ? "1" : "0"));
    
    if (m_bDirty && bWrite && IsExternal(sFileName))
    {
        LOG("BLOCKED WRITE: " << sFileName.c_str());
        return false;
    }
    
    if (sFileName.find("confidential") != string::npos)
        m_bDirty = true;

    return true;
}

bool CDLPEngineProto::IsExternal(const std::string& sFileName)
{
    return (sFileName.find("/media/") != string::npos ||
            sFileName.find("external") != string::npos);
}

