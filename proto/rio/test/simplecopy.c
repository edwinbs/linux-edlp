#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    int x = 0;
    char *buff = (char *) malloc(5);
    struct FILE *fsrc = fopen(argv[1], "r");
    struct FILE *fdst = fopen(argv[2], "a");
    
    memset((void *) buff, 0, 5);
    fgets(buff, 5, fsrc);
    fputs(buff, fdst);
    
    fclose(fsrc);
    fclose(fdst);
    free(buff);

    return 0;
}
