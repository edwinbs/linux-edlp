#include <stdio.h>
#include <syscall.h>
#include <stdint.h>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <set>
#include <map>
#include "pin.H"

#define _VERBOSE 0

using namespace std;

typedef struct SSyscallInfo
{
    uint32_t    no;
    ADDRINT     arg0;
    ADDRINT     arg1;
    ADDRINT     arg2;
    ADDRINT     arg3;
    ADDRINT     arg4;
    ADDRINT     ret;
    
    SSyscallInfo()
    : no(0), arg0(0), arg1(0), arg2(0), arg3(0), arg4(0), ret(0) { };
    
} syscall_info_t;

FILE * trace;
static uint8_t* shblk[0x10000];
static uint8_t shgpr[8];
static uint8_t other_regs[0x100];

static uint8_t current_taint_flag;

static set<int> setTaintedFDs;
static set<int> setExternalFDs;

//static syscall_info_t syscallInfo;
static map<THREADID, syscall_info_t> mapSyscallInfo;


inline static uint8_t* GetShadowPtr(uint32_t addr)
{
    uint8_t** shadow_pp = &shblk[(addr >> 16) & 0xffff];
    
    if (!(*shadow_pp)) /* shadow block has not been allocated */
    {
        *shadow_pp = (uint8_t*) malloc(0x10000 * sizeof(uint8_t));
        memset(*shadow_pp, 0, 0x10000 * sizeof(uint8_t));
    }
        
    return &((*shadow_pp)[(addr & 0xffff)]);
}

bool IsFileExternal(const string& pathname)
{
    if (pathname.find("/media/") != string::npos ||
        pathname.find("external_test/") != string::npos)
    {
        return true;
    }
    
    return false;
}

bool IsFileConfidential(const string& pathname)
{
    if (pathname.find("confidential") != string::npos)
        return true;
        
    return false;
}

inline uint8_t* GetShadowReg(uint32_t reg)
{
    switch (reg)
    {
    case REG_EAX: case REG_AX: case REG_AL: case REG_AH: return &(shgpr[0]);
    case REG_ECX: case REG_CX: case REG_CL: case REG_CH: return &(shgpr[1]);
    case REG_EDX: case REG_DX: case REG_DL: case REG_DH: return &(shgpr[2]);
    case REG_EBX: case REG_BX: case REG_BL: case REG_BH: return &(shgpr[3]);
    case REG_ESP: return &(shgpr[4]);
    case REG_EBP: return &(shgpr[5]);
    case REG_ESI: return &(shgpr[6]);
    case REG_EDI: return &(shgpr[7]);
    }
    return &(other_regs[reg]);
}

bool BeforeWrite(ADDRINT fd, ADDRINT buf, ADDRINT count)
{
    if (setExternalFDs.find(fd) == setExternalFDs.end()) //Not external location
        return true;

    for (ssize_t i = 0; i < (ssize_t) count; ++i)
    {
        if (*(GetShadowPtr((uint32_t) buf + i)))
        {
            fprintf(trace, "Tainted write % 4d bytes to fd=0x%x from 0x%08x\n",
                (ssize_t) count, (int) fd, (uint32_t) buf);
            fprintf(stderr, "[DLP] Blocked write.\n");
            return false;
        }
    }
    
    fprintf(trace, "Clean write % 4d bytes to fd=0x%x from 0x%08x\n",
        (ssize_t) count, (int) fd, (uint32_t) buf);
    
    return true;
}

VOID AfterRead(ADDRINT fd, ADDRINT buf, ADDRINT count, ADDRINT bytes_read)
{
    if (setTaintedFDs.find((int) fd) != setTaintedFDs.end())
    {
        fprintf(trace, "Tainted load % 4d bytes to 0x%08x\n",
            (ssize_t) bytes_read, (uint32_t) buf);
        
        for (ssize_t i = 0; i < (ssize_t) bytes_read; ++i)
        {
            uint8_t* shadow_ptr = GetShadowPtr((uint32_t) buf + i);
            *shadow_ptr = 1;
        }
    }
}

VOID AfterOpen(ADDRINT pathname, ADDRINT flags, ADDRINT fd)
{
    bool is_tainted = false;
    
    if (IsFileConfidential((const char*) pathname))
    {
        setTaintedFDs.insert(fd);
        is_tainted = true;
    }
    
    if (IsFileExternal((const char*) pathname))
    {
        setExternalFDs.insert(fd);
    }
    
    fprintf(trace, "OPEN [%s] = 0x%x %s\n", (const char*) pathname, (int) fd, is_tainted?"(tainted)":"");
    fflush(trace);
}

bool BeforeClose(ADDRINT fd)
{
    set<int>::iterator it1 = setTaintedFDs.find(fd);
    if (it1 != setTaintedFDs.end())
    {
        setTaintedFDs.erase(it1);
    }
    
    set<int>::iterator it2 = setExternalFDs.find(fd);
    if (it2 != setExternalFDs.end())
    {
        setExternalFDs.erase(it2);
    }
    
    return true;
}

VOID ResetCurrentTaintFlag()
{
    current_taint_flag = 0;
}

VOID CheckMemRead(VOID* ip, UINT32 opcode, VOID* addr, UINT32 size)
{
    for (UINT32 i = 0; i < size; ++i)
    {
        uint8_t* shadow = GetShadowPtr((uint32_t) addr+i);
        current_taint_flag |= *shadow;
#if _VERBOSE
        if (*shadow)
            fprintf(trace, "[%p] [%d] Tainted MEM read: 0x%x\n", ip, opcode, (uint32_t) addr+i);
#endif
    }
}

VOID CheckMemWrite(VOID* ip, UINT32 opcode, VOID* addr, UINT32 size)
{
    for (UINT32 i = 0; i < size; ++i)
    {
        uint8_t* shadow = GetShadowPtr((uint32_t) addr+i);
        *shadow = current_taint_flag;
#if _VERBOSE
        if (*shadow)
            fprintf(trace, "[%p] [%d] Tainted MEM write: 0x%x\n", ip, opcode, (uint32_t) addr+i);
#endif
    }
}

VOID CheckRegRead(VOID* ip, UINT32 opcode, UINT32 reg)
{
    uint8_t* shadow = GetShadowReg(reg);
    current_taint_flag |= *shadow;
#if _VERBOSE
    if (*shadow)
        fprintf(trace, "[%p] [%d] Tainted REG read: 0x%x\n", ip, opcode, reg);
#endif
}

VOID CheckRegWrite(VOID* ip, UINT32 opcode, UINT32 reg)
{
    uint8_t* shadow = GetShadowReg(reg);
    *shadow = current_taint_flag;
#if _VERBOSE
    if (*shadow)
        fprintf(trace, "[%p] [%d] Tainted REG write: 0x%x\n", ip, opcode, reg);
#endif
}

VOID OnSyscallEntry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    bool allowed = true;
    
    mapSyscallInfo[tid].no   = PIN_GetSyscallNumber(ctxt, std);
    mapSyscallInfo[tid].arg0 = PIN_GetSyscallArgument(ctxt, std, 0);
    mapSyscallInfo[tid].arg1 = PIN_GetSyscallArgument(ctxt, std, 1);
    mapSyscallInfo[tid].arg2 = PIN_GetSyscallArgument(ctxt, std, 2);
    mapSyscallInfo[tid].arg3 = PIN_GetSyscallArgument(ctxt, std, 3);
    mapSyscallInfo[tid].arg4 = PIN_GetSyscallArgument(ctxt, std, 4);
    
    switch (mapSyscallInfo[tid].no)
    {  
    case SYS_write:
        allowed = BeforeWrite(
            mapSyscallInfo[tid].arg0,   //fd
            mapSyscallInfo[tid].arg1,   //buf
            mapSyscallInfo[tid].arg2);  //count
        break;
        
    case SYS_close:
        allowed = BeforeClose(
            mapSyscallInfo[tid].arg0);  //fd
    }
    
    if (!allowed)
        PIN_SetSyscallNumber(ctxt, std, SYS_idle); // Block the call
}

VOID OnSyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    mapSyscallInfo[tid].ret = PIN_GetSyscallReturn(ctxt, std);

    switch (mapSyscallInfo[tid].no)
    {
    case SYS_open:
        AfterOpen(
            mapSyscallInfo[tid].arg0,   //pathname
            mapSyscallInfo[tid].arg1,   //flags
            mapSyscallInfo[tid].ret);   //fd
        break;
    
    case SYS_read:
        AfterRead(
            mapSyscallInfo[tid].arg0,   //fd
            mapSyscallInfo[tid].arg1,   //buf
            mapSyscallInfo[tid].arg2,   //count
            mapSyscallInfo[tid].ret);   //bytes_read
        break;
    }
}

VOID OnNewInstruction(INS ins, VOID *v)
{
    UINT32 memCnt = INS_MemoryOperandCount(ins);
    UINT32 dstMemCnt = 0, dstRegCnt = 0;
    
    // Check if there is any write operation
    for (UINT32 i = 0; i < memCnt; ++i)
    {
        if (INS_MemoryOperandIsWritten(ins, i))
            ++dstMemCnt;
    }
    
    dstRegCnt = INS_MaxNumWRegs(ins);
    
    if (dstMemCnt <= 0 && dstRegCnt <= 0) // No dst, do not instrument
        return;
        
    INS_InsertPredicatedCall(
        ins, IPOINT_BEFORE, (AFUNPTR) ResetCurrentTaintFlag,
        IARG_END);
    
    // We cannot iterate all mems first, must do SRC first then DST
    
    //-----Source-----
    
    for (UINT32 i = 0; i < memCnt; ++i)
    {
        if (INS_MemoryOperandIsRead(ins, i))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR) CheckMemRead,
                IARG_INST_PTR,
                IARG_UINT32, (UINT32) INS_Category(ins),
                IARG_MEMORYOP_EA, i,
                IARG_UINT32, (UINT32) INS_MemoryWriteSize(ins),
                IARG_END);
        }
    }
    
    UINT32 opndCnt = INS_OperandCount(ins);
    for (UINT32 i = 0; i < opndCnt; ++i)
    {
        if (INS_OperandRead(ins, i))
        {
            if (INS_OperandIsReg(ins, i))
            {
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR) CheckRegRead,
                    IARG_INST_PTR,
                    IARG_UINT32, (UINT32) INS_Category(ins),
                    IARG_UINT32, (UINT32) INS_OperandReg(ins, i),
                    IARG_END);
            }
        }
    }
    
    //----- Destination-----
    
    for (UINT32 i = 0; i < memCnt; ++i)
    {
        if (INS_MemoryOperandIsWritten(ins, i))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR) CheckMemWrite,
                IARG_INST_PTR,
                IARG_UINT32, (UINT32) INS_Category(ins),
                IARG_MEMORYOP_EA, i,
                IARG_UINT32, (UINT32) INS_MemoryWriteSize(ins),
                IARG_END);
        }
    }
    
    for (UINT32 i = 0; i < opndCnt; ++i)
    {
        if (INS_OperandWritten(ins, i))
        {
            if (INS_OperandIsReg(ins, i))
            {
                INS_InsertPredicatedCall(
                    ins, IPOINT_BEFORE, (AFUNPTR) CheckRegWrite,
                    IARG_INST_PTR,
                    IARG_UINT32, (UINT32) INS_Category(ins),
                    IARG_UINT32, (UINT32) INS_OperandReg(ins, i),
                    IARG_END);
            }
        }
    }
}

BOOL OnNewChild(CHILD_PROCESS childProcess, VOID* userData)
{
    return TRUE;
}

VOID OnFinish(INT32 code, VOID *v)
{
    fprintf(trace, "Tainted locations:\n");
    for (uint16_t hi=0; hi<0xffff; ++hi)
    {
        if (!shblk[hi]) continue;
        
        for (uint16_t lo=0; lo<0xffff; ++lo)
        {
            if (shblk[hi][lo])
                fprintf(trace, "0x%04x%04x\n", hi, lo);
        }
    }
    
    fflush(trace);
    fclose(trace);
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
        return -1;

    trace = fopen("dlp.out", "w");
    
    memset(shblk, 0, 0x10000 * sizeof(uint8_t));
    memset(shgpr, 0, 8 * sizeof(uint8_t));
    memset(other_regs, 0, 0x100 * sizeof(uint8_t));

    INS_AddInstrumentFunction(OnNewInstruction, 0);
    PIN_AddSyscallEntryFunction(OnSyscallEntry, 0);
    PIN_AddSyscallExitFunction(OnSyscallExit, 0);
    PIN_AddFollowChildProcessFunction(OnNewChild, 0);

    PIN_AddFiniFunction(OnFinish, 0);
    
    PIN_StartProgram();
    
    return 0;
}
