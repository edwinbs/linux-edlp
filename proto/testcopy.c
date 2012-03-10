#include <stdlib.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        printf("Usage: testcopy [source] [destination]\n");
        return 1;
    }
    
    FILE* pSrc = fopen(argv[1], "r");
    if (!pSrc)
    {
        printf("Cannot open %s\n", argv[1]);
        return 1;
    }
    
    fseek(pSrc, 0, SEEK_END);
    long lSize = ftell(pSrc);
    rewind(pSrc);
    
    char* pBuf = (char*) malloc(sizeof(char) * lSize);
    if (!pBuf)
    {
        printf("Out of memory\n");
        fclose(pSrc); pSrc = NULL;
        return 1;
    }
    
    size_t nCount = fread(pBuf, 1, lSize, pSrc);
    if (nCount != lSize)
    {
        printf("Reading error\n");
        fclose(pSrc); pSrc = NULL;
        return 1;
    }
    
    fclose(pSrc); pSrc = NULL;
    
    FILE* pDst = fopen(argv[2], "w");
    if (!pDst)
    {
        printf("Cannot write %s\n", argv[2]);
        return 2;
    }
    
    size_t nWritten = fwrite(pBuf, 1, lSize, pDst);
    if (nWritten != lSize)
    {
        printf("Writing error\n");
        fclose(pDst); pDst = NULL;
        return 2;
    }
    
    fclose(pDst); pDst = 0;
    
    if (pBuf)
    {
        free(pBuf); pBuf = 0;
    }
    
    return 0;
}
