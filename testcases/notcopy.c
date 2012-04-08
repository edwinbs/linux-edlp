#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int main(int argc, char** argv)
{
    FILE* pSrc = fopen(argv[1], "r");
    
    fseek(pSrc, 0, SEEK_END);
    long lSize = ftell(pSrc);
    rewind(pSrc);
    
    char* pBuf = (char*) malloc(sizeof(char) * lSize);
    
    size_t nCount = fread(pBuf, 1, lSize, pSrc);
    
    fclose(pSrc); pSrc = NULL;
    
    FILE* pDst = fopen(argv[2], "w");
    
    size_t nWritten = fwrite("notcopy\n", 1, 9, pDst);
    
    fclose(pDst); pDst = 0;
    
    if (pBuf)
    {
        free(pBuf); pBuf = 0;
    }
    
    return 0;
}
