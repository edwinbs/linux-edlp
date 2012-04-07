#pragma once

#include "logger.h"

# define FILE_TYPE_NORMAL   0
# define FILE_TYPE_TAINTED  1
# define FILE_TYPE_EXTERNAL 2

struct SThreadData
{
    Logger m_logger;
    int m_iFileType;
    reg_t* m_rgArgs;

    SThreadData()
	: m_iFileType(FILE_TYPE_NORMAL)
	, m_rgArgs(NULL)
    {
	//m_logger.Initialize(LOGGER_FILE);
    }
};

// The index for thread local storage
static int tlsIdx;

/* Shadow memory (32-bit) */
/* 64K blocks of 64KB each. shblk[] contain the pointer to the real blocks. */
/* Note that the block pointers consume (64 * 4 = 256) KB */
static uint8_t** shblk = NULL;

/* Shadow of IA32 General Purpose Registers */
static uint8_t shgpr[8];

// Get the pointer to the flags block in the 2-D array
inline static uint8_t* get_shadow_ptr(uint32_t addr)
{
    // Lazy allocation; probably not of any use for tainted programs.
    // However, will save something for programs that don't load tainted files.
    if (shblk == NULL)
    {
	shblk = (uint8_t **) dr_global_alloc(0xffff * sizeof(uint8_t*));
	memset(shblk, 0, 0xffff * sizeof(uint8_t*));
    }

    uint16_t ho_idx = (uint16_t) ((addr >> 16) & 0xffff);
    uint8_t* lo_blk = shblk[ho_idx];
    if (lo_blk == NULL)
    {
	lo_blk = (uint8_t *) dr_global_alloc(0xffff * sizeof(uint8_t));
	memset(lo_blk, 0, 0xffff * sizeof(uint8_t));
	shblk[ho_idx] = lo_blk;
    }
    
    uint16_t lo_idx = (uint16_t) addr;
    return &(lo_blk[lo_idx]);
}

inline static bool is_tainted_buf(void *buf, size_t size)
{
    void *ptr = buf;
    for (int i = 0; i < size; i++, ptr = ptr + 1)
    {	
	uint32_t addr = (uint32_t) ptr;
	uint8_t *pFlags = get_shadow_ptr(addr);
	if (*pFlags == 1)
	    return true;
    }

    return false;
}
