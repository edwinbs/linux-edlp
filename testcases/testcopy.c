#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char** argv)
{
    FILE* pSrc = fopen(argv[1], "r");
    
    fseek(pSrc, 0, SEEK_END);
    long lSize = ftell(pSrc);
    rewind(pSrc);
    
    char* pBuf = (char*) malloc(sizeof(char) * lSize);
    
    size_t nCount = fread(pBuf, 1, lSize, pSrc);
    
    fclose(pSrc); pSrc = NULL;
    
    char* pBuf2 = (char*) malloc(sizeof(char) * lSize);
    
    printf("source buf=0x%x - 0x%x, dest buf=0x%x - 0x%x\n",
        (uint32_t) pBuf,
        (uint32_t) (pBuf + lSize - 1),
        (uint32_t) pBuf2,
        (uint32_t)(pBuf2 + lSize - 1));
    
    memcpy((void*) pBuf2, (void*) pBuf, lSize * sizeof(char));
    
    FILE* pDst = fopen(argv[2], "w");
    
    size_t nWritten = fwrite(pBuf2, 1, lSize, pDst);
    
    fclose(pDst); pDst = 0;
    
    if (pBuf)
    {
        free(pBuf); pBuf = 0;
    }
    
    if (pBuf2)
    {
        free(pBuf2); pBuf2 = 0;
    }
    
    return 0;
}
