#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#define CHECKED_ALLOC(sz) checked_alloc(sz, __FILE__, __LINE__)

#define HANDLE_TERM(sig) handle_term(sig, __FILE__, __LINE__)

static volatile int done = 0;

struct memhog_opts_t {
    size_t bytes;
    int lock_addr_only;
    int lock_future;
};

void *checked_alloc(size_t sz, const char *name, int lineno)
{
    void *ptr;
    if ((ptr = malloc(sz)) == NULL) {
        fprintf(stderr, "malloc() near %s:%d: %s\n", name, lineno,
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void handler(int signum)
{
    done = 1;  
}

int handle_term(int sig, const char *name, int lineno)
{
    int ret = 1;
    if (signal(sig, handler) == SIG_ERR) {
        fprintf(stderr, "signal() near %s:%d: %s\n", name, lineno,
                strerror(errno));
        ret = 0;
    }
    return ret;
}

int hog(struct memhog_opts_t *opts)
{
    void *ptr = NULL;
    int ret = 0;
    size_t bytes = opts->bytes;
    int lock_future = opts->lock_future;
    
    if (lock_future) {
        if (mlockall(MCL_FUTURE) != 0) {
            perror("mlockall()");
            goto error_ret;
        }
    }
    
    ptr = CHECKED_ALLOC(bytes);

    if (!lock_future) {
        if (opts->lock_addr_only) {
            if (mlock(ptr, opts->bytes) != 0) {
                perror("mlock()");
                goto error_free;
            }
        } else {
            if (mlockall(MCL_CURRENT) != 0) {
                perror("mlockall()");
                goto error_free;
            }
        }
    }

    if (!(HANDLE_TERM(SIGINT) && HANDLE_TERM(SIGHUP) &&
          HANDLE_TERM(SIGTERM))) {
        goto error_unlock;
    }

    if (!done) {
        pause();
    }
    
 error_unlock:
    if (opts->lock_addr_only) {
        if (munlock(ptr, bytes) != 0) {
            perror("munlock()");
        }
    } else {
        if (munlockall() != 0) {
            perror("munlock()");
        }
    }
 error_free:
    free(ptr);
 error_ret:
    return ret;
}

void usage(const char *progname, const char *msg)
{
    if (msg != NULL) {
        fprintf(stderr, "%s\n", msg);
    }
    fprintf(stderr, "Usage: %s <options> bytes\n", progname);
    fprintf(stderr, "a|addr -- only lock the pointer itself\n");
    fprintf(stderr, "f|future -- lock the pages early with MCL_FUTURE\n");
}

int main(int argc, char** argv)
{
    size_t bytes;
    struct memhog_opts_t opts;
    static const struct option getopt_long_opts[] = {
        { "addr", no_argument, NULL, 'a' },
        { "future", no_argument, NULL, 'f' },
        { NULL, no_argument, NULL, 0 }
    };
    int ret = EXIT_FAILURE;

    memset(&opts, 0, sizeof(opts));
    
    while (1) {
        int opt_index = 0;
        int opt = getopt_long(argc, argv, "afh?", getopt_long_opts,
                              &opt_index);
        if (opt == -1) {
            break;
        }
        switch (opt) {
        case 'a':
            opts.lock_addr_only = 1;
            break;
        case 'f':
            opts.lock_future = 1;
            break;
        case 'h':
        case '?':
            usage(argv[0], NULL);
            goto early_exit;
        default:
            /* won't get here */
            break;
        }
    }

    if (opts.lock_addr_only && opts.lock_future) {
        usage(argv[0], "both addr and future can't both be set!");
        goto early_exit;
    }
    if (optind < argc) {
         bytes = strtoul(argv[optind], NULL, 10);
         if (bytes < 1) {
             usage(argv[0], "bytes must be a positive integer");
             goto early_exit;
         }
    } else {
        usage(argv[0], NULL);
        goto early_exit;
    }

    opts.bytes = bytes;
    ret = hog(&opts) ? EXIT_SUCCESS : EXIT_FAILURE;
    printf("Exiting...\n");

 early_exit:
    return ret;
}
