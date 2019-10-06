#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#include "flexsc_syscalls.h"

#define MAX_THREAD 10000 /* page-dependent DONT CHANGE (write() testing) */

//#define FLEXSC
//#define NORMAL

#ifdef FLEXSC
#define LOG_FILE_NAME "flexSC_logfile_flex.txt"
#else
#define LOG_FILE_NAME "flexSC_logfile_normal.txt"
#endif

struct flexsc_init_info *flexsc_info;
pthread_spinlock_t spin_logfile;
FILE *fd;
pthread_t pt[MAX_THREAD];
static const char dummy_str[10] = "ABCDEFGHI";
int fd_perf;

static inline long get_diff_timespec_ns(struct timespec *start, struct timespec *end)
{
    return ((end->tv_sec - start->tv_sec) * 1000000000) + end->tv_nsec - start->tv_nsec;
}

void *worker(void *arg)
{
    int no = (int) arg;

    struct timespec start, end;
    long ret;
 
    clock_gettime(CLOCK_REALTIME, &start);
#ifdef FLEXSC
    //ret = flexsc_getpid(0);
    ret = flexsc_write(0, dummy_str, no, 0); /* we take `no` as index to shared page */
#else
    //ret = getpid();
    //ret = write(fd_perf, dummy_str, 10);
    ret = syscall(1, fd_perf, dummy_str, 10);
    //ret = syscall(39);
#endif
    clock_gettime(CLOCK_REALTIME, &end);

    /* write() validation */
    if (unlikely(10 != ret)) {
        printf("write() validation failed (ret = %ld)\n", ret);
        exit(-1);
    }

    /* if the stdout is messed up, add this into the crit section below */
    //printf("syscall retval: %ld\n", ret);
    pthread_spin_lock(&spin_logfile);
    //fprintf(fd, "%d %ld %ld\n", gettid(), res.tv_sec, res.tv_nsec);   
    fprintf(fd, "%d %ld\n", no, get_diff_timespec_ns(&start, &end)/* (res.tv_sec * ((long) 1e9) ) + res.tv_nsec */);
    pthread_spin_unlock(&spin_logfile);

    pthread_exit(NULL);
}

int create_pthread(int num)
{
    int i = 0;

    for (;i < num; i++) {
        pthread_create(&pt[i], NULL, worker, (void*) i);
        if (!pt[i]) {
            puts("Erorr: worker thread creation failed");
            return -1;
        }
    }

    return 0;
}

int main(void)
{
    long ret;

    if (pthread_spin_init(&spin_logfile, PTHREAD_PROCESS_PRIVATE)) {
        puts("Error: pthread_spin_init() failed");
        goto err_spin_init;
    }

    fd = fopen(LOG_FILE_NAME, "w");
    if (!fd) {
        perror("Error, open logfile failed:");
        goto err_fopen;
    }

#ifdef FLEXSC
    flexsc_info = (struct flexsc_init_info*) malloc(sizeof(struct flexsc_init_info));

    if (0 > flexsc_register(flexsc_info)) {
        puts("registration of FlexSC failed");
        goto err_register;
    }

    puts("done flexsc registration");
    flexsc_start_syscall();

#else
    fd_perf = open("/dev/null", O_WRONLY);
#endif

    if (create_pthread(MAX_THREAD))
        goto err_pthread;

#ifdef FLEXSC
    /* finish the rest of the syscalls */
#endif

    for (int i = 0; i < MAX_THREAD; i++)
        pthread_join(pt[i], NULL);
    puts("all app threads have ended");

    fflush(fd); // due to panic at flexsc_exit(), we force write back, or some result may lost

    //printf("flexsc syscall done with retval: %ld\n", ret);
#ifdef FLEXSC
    //sleep(1);

    ret = flexsc_exit();

    printf("flexsc exit retval: %ld\n", ret);
#endif
    fclose(fd);

    return 0;

err_pthread:
    fclose(fd);
err_fopen:
err_spin_init:
err_register:
    return -1;
}
