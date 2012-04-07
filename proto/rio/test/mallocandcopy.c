#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    int x = 0;
    char *buff = (char *) malloc(5);
    char *buff1 = NULL;
    struct FILE *fsrc = fopen(argv[1], "r");
    struct FILE *fdst = fopen(argv[2], "a");
    
    memset((void *) buff, 0, 5);
    fgets(buff, 5, fsrc);
    buff1 = (char*) malloc(5);
    memcpy(buff1, buff, 5);
    free(buff);
    fputs(buff1, fdst);
    
    fclose(fsrc);
    fclose(fdst);
    free(buff1);

    return 0;
}
