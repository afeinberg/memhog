#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

static volatile int done = 0;

void handler(int signum)
{
    done = 1;  
}

int install_handler(int sig)
{
    if (signal(sig, handler) == SIG_ERR) {
        perror("signal()");
        return 0;
    }
    return 1;
}
                         
int main(int argc, char** argv)
{
    size_t alloc_bytes;
    void *ptr;
    int ret = EXIT_FAILURE;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s bytes\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    alloc_bytes = atol(argv[1]);
    assert(alloc_bytes > 0);    
    assert((ptr = malloc(alloc_bytes)) != NULL);

    if (mlockall(MCL_CURRENT) != 0) {
        perror("mlock()");
        goto error_free;
    }
    
    if (!install_handler(SIGINT))
        goto error_munlock;
    if (!install_handler(SIGHUP))
        goto error_munlock;
    if (!install_handler(SIGTERM))
        goto error_munlock;
    
    while (!done) {
        pause();
    }

    printf("Exiting..\n");
    ret = EXIT_SUCCESS;
    
 error_munlock:
    if (munlockall() != 0) {
        perror("munlock()");
    }
    
 error_free:
    if (ptr != NULL) {
        free(ptr);
    }
    
    return ret;
}
