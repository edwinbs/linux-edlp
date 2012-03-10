#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <dlfcn.h>
#include <sys/stat.h> 

#include "dlpengine_proto.cc"

#ifdef __cplusplus
extern "C" {

namespace
{
    CDLPEngineProto g_dlp;
};

using namespace std;

typedef int (*pf_open_t)(const char *fn, int flags);
int open(const char *fn, int flags) {
    static pf_open_t sys_open;

    if (!sys_open) {
        sys_open = (pf_open_t) dlsym(RTLD_NEXT, "open");
    }
    
    bool bWrite = false; //TODO: what are the flags?

    if (g_dlp.OnOpen(fn))
        return sys_open(fn, flags);
    
    return 0;
}

typedef FILE* (*pf_fopen_t)(const char *path, const char *mode);
FILE *fopen(const char *path, const char *mode)
{
    static pf_fopen_t sys_fopen;
    
    if (!sys_fopen) {
        sys_fopen = (pf_fopen_t) dlsym(RTLD_NEXT, "fopen");
    }
    
    string sMode(mode);
    bool bWrite = (sMode.find("w") != string::npos || sMode.find("a") != string::npos);
    
    if (g_dlp.OnOpen(path, bWrite))
        return sys_fopen(path, mode);
        
    return NULL;
}

typedef FILE* (*pf_freopen_t)(const char *path, const char *mode, FILE *stream);
FILE *freopen(const char *path, const char *mode, FILE *stream)
{
    static pf_freopen_t sys_freopen;
    
    if (!sys_freopen) {
        sys_freopen = (pf_freopen_t) dlsym(RTLD_NEXT, "freopen");
    }
    
    string sMode(mode);
    bool bWrite = (sMode.find("w") != string::npos || sMode.find("a") != string::npos);
    
    if (g_dlp.OnOpen(path, bWrite))
        return sys_freopen(path, mode, stream);
        
    return NULL;
}

}
#endif
