#include "flexsc_syscalls.h"
#include "string.h"
/** WARN:
 * Only write() is implemented properly now, others are TODO.
 * 
 * Note that if kernel-visible thread scanning sysentries dynamically and
 * issues flexsc_wait, we should implement a memory barrier-like
 * mechanism to prevent a syscall got executed before user mode thread
 * done populating syscall-related args.
 */

extern pthread_cond_t user_wait;
extern pthread_mutex_t user_wait_cond;
extern pthread_spinlock_t spin_free_entry, spin_user_pending;
extern uint8_t syscall_runner;
extern struct flexsc_init_info *u_info;


static inline void request_syscall_write(struct flexsc_sysentry *entry, unsigned int fd, char  *buf, size_t count);
static inline ssize_t _flexsc_write(unsigned int fd, char  *buf, size_t count);
static inline pid_t _flexsc_getpid(void);

static struct flexsc_sysentry *get_free_syscall_entry(void)
{
retry:
    pthread_spin_lock(&spin_free_entry);

    for (int i = 0; i < u_info->npages; i++) {
        if (u_info->sysentry[i].rstatus == FLEXSC_STATUS_FREE) {
            /**
             * change rstatus to BUSY due to the page may being robbed once the lock is released
             * because it is not set to !FREE immediately after accquired by current thread.
             */
            u_info->sysentry[i].rstatus = FLEXSC_STATUS_BUSY;
            pthread_spin_unlock(&spin_free_entry);
            //printf("entry found (i = %d)\n", i);
            return &u_info->sysentry[i];
        }
    }

    pthread_spin_unlock(&spin_free_entry);
    //puts("entry not found");

/**
 * if we have plenty of user threads waiting here, we may facing high usage issue,
 * but if we use pthread_cond_wait on this, the wake up time from cond_wait
 * may be the penalty of performance.
 */
    //pthread_spin_lock(&spin_user_pending); //seems this is not need, because the correctness is not affected by it

    if (syscall_runner == IDLE)
        syscall_runner = IN_PROGRESS;
    else if (syscall_runner == DONE) {
        puts("warning: get free syscall page at DONE state");
        syscall_runner = IN_PROGRESS;
    }

    //pthread_spin_unlock(&spin_user_pending);

    pthread_yield();
    goto retry;
}

static inline ssize_t _flexsc_write(unsigned int fd, char *buf, size_t count)
{
    long retval;

    struct flexsc_sysentry *entry;

    entry = get_free_syscall_entry();
    request_syscall_write(entry, fd, buf, count);

    memcpy(u_info->write_page + (count * 10 /* sizeof dummy string */), buf, 10);

    //asm volatile ("" : : : "memory");
    __sync_synchronize();

    entry->rstatus = FLEXSC_STATUS_SUBMITTED;
    //puts("syspage submitted");
    //pthread_mutex_lock(&user_wait_cond);
    /**
     * note that if we got bad performance, we can try to modify the impl here
     * with pthread_yield(), since I believe that syscalls in flexsc is 
     * pretty fast to done. But also be aware that performance may be even poor
     * when syscall requests are few due to long CPU resources holding time.
     *
     * another concern is that I'm not sure if user thread will all go to sleep
     * once the process has been halted with:
     * 
     * set_current_state(TASK_INTERRUPTIBLE);
     * schedule();
     * 
     * it should does make all threads belong to the calling process go to sleep
     * but I'm not 100% sure. If they doesn't sleep, then our user threads may
     * consume plenty of CPU resources. Hence, this is a TODO TEST.
     */ 
    /*
    while (entry->rstatus != FLEXSC_STATUS_DONE) {
        pthread_cond_wait(&user_wait, &user_sleep_cond);
    }
    */
    /**
     * only wait at cond once, if we are waken up, we use pthread_yield() to wait
     * since the syscall entry may being processed in short time.
     */
/*
    while (entry->rstatus != FLEXSC_STATUS_DONE) {
        pthread_cond_wait(&user_wait, &user_wait_cond);
    }
    
    pthread_mutex_unlock(&user_wait_cond);
*/
    while (entry->rstatus != FLEXSC_STATUS_DONE) {
        pthread_yield();
    }
        
    /**
     * To validate correctness of syscall, we should use arbitrary `size` (arbitrary bitwise shifting might be a good way, which only
     * produce divide-by-2-able `size`) which as arg of syscall write() (why mention write(), because it's the syscall we fully implemented
     * currently)
     * 
     * Note: once we set the rstatus to FLEXSC_STATUS_FREE, the args field may being changed by other syscall requester, hence we save it to
     * local var first to ensure we have correct retval of the syscall.
     * 
     * Note: since entry->sysret has type `unsigned`, which can't accomodate type `long`, we deprecate it as return value of the syscall
     */
    retval = entry->args[0];

    entry->rstatus = FLEXSC_STATUS_FREE;

    return retval;
}

/**
 * @brief flexSC-ver write syscall
 * @fd as original
 * @buf as original
 * @count as original
 * @exe whether the syscall should start immediately, if false, the syscall
 * simply wait for calling of flexsc_start_syscall() or the full of syscall page
 */
ssize_t flexsc_write(unsigned int fd, char *buf, size_t count, int exe)
{
    if (unlikely(exe)) {
        pthread_spin_lock(&spin_user_pending);
        syscall_runner = IN_PROGRESS;
        pthread_spin_unlock(&spin_user_pending);
    }
    
    return (ssize_t) _flexsc_write(fd, buf, count);
}

struct flexsc_sysentry* flexsc_getppid()
{
    struct flexsc_sysentry *entry;
    entry = get_free_syscall_entry();
    entry->sysnum = __NR_getppid;
    entry->nargs = __ARGS_getppid;
    entry->rstatus = FLEXSC_STATUS_SUBMITTED;
    return entry;
}

static inline pid_t _flexsc_getpid(void)
{
    long retval;

    struct flexsc_sysentry *entry;

    entry = get_free_syscall_entry();

    request_syscall_getpid(entry);
    //asm volatile ("" : : : "memory");
    __sync_synchronize();
    entry->rstatus = FLEXSC_STATUS_SUBMITTED;

    //pthread_mutex_lock(&user_wait_cond);
/*
    if (entry->rstatus != FLEXSC_STATUS_DONE) {
        pthread_cond_wait(&user_wait, &user_wait_cond);
    }
*/    

    //pthread_mutex_unlock(&user_wait_cond);

    /* release the lock and wait here alone */
    while (entry->rstatus != FLEXSC_STATUS_DONE) {
        pthread_yield();
    }
/*
    while (entry->rstatus != FLEXSC_STATUS_DONE) {
        pthread_cond_wait(&user_wait, &user_wait_cond);
    }
    
    pthread_mutex_unlock(&user_wait_cond);
*/    
    /**
     * Note: once we set the rstatus to FLEXSC_STATUS_FREE, the args field may being changed by other syscall requester, hence we save it to
     * local var first to ensure we have correct retval of the syscall.
     * 
     * Note: since entry->sysret has type `unsigned`, which can't accomodate type `long`, we deprecate it as return value of the syscall
     */
    retval = entry->args[0];

    entry->rstatus = FLEXSC_STATUS_FREE;

    return retval;
}

pid_t flexsc_getpid(int exe)
{
    if (unlikely(exe)) {
        pthread_spin_lock(&spin_user_pending);
        syscall_runner = IN_PROGRESS;
        pthread_spin_unlock(&spin_user_pending);
    }

    return (pid_t) _flexsc_getpid();
}

struct flexsc_sysentry* flexsc_read(unsigned int fd, char  *buf, size_t count)
{
    struct flexsc_sysentry *entry;
    entry = get_free_syscall_entry();
    request_syscall_read(entry, fd, buf, count);
    return entry;
}

struct flexsc_sysentry* flexsc_stat(const char *pathname, struct stat *statbuf)
{
    struct flexsc_sysentry *entry;
    entry = get_free_syscall_entry();
    request_syscall_stat(entry, pathname, statbuf);
    return entry;
}


void request_syscall_stat(struct flexsc_sysentry *entry, const char *pathname, struct stat *statbuf)
{
    entry->sysnum = __NR_stat;
    entry->nargs = __ARGS_stat;
    entry->rstatus = FLEXSC_STATUS_SUBMITTED;
    entry->args[0] = (long)pathname;
    entry->args[1] = (long)statbuf;
}

void request_syscall_read(struct flexsc_sysentry *entry, unsigned int fd, char *buf, size_t count)
{
    entry->sysnum = __NR_read;
    entry->nargs = __ARGS_read;
    entry->rstatus = FLEXSC_STATUS_SUBMITTED;
    entry->args[0] = (long)fd;
    entry->args[1] = (long)buf;
    entry->args[2] = (long)count;
}

/**
 * If syscall executed by FlexSC got wrong return value, you may suspect that if this func need a 
 * memory barrier, since kthreads may start execution of syscall before user threads done population
 * of these args, nargs, and sysnum, etc.
 */
static inline void request_syscall_write(struct flexsc_sysentry *entry, unsigned int fd, char *buf, size_t count)
{
    entry->sysnum = __NR_write;
    entry->nargs = __ARGS_write;
    entry->args[0] = (long)fd;
    entry->args[1] = (long)buf;
    entry->args[2] = (long)count;
}

void request_syscall_open(struct flexsc_sysentry *entry, const char  *filename, int flags, mode_t mode)
{
    entry->sysnum = __NR_open;
    entry->nargs = __ARGS_open;
    entry->rstatus = FLEXSC_STATUS_SUBMITTED;
    entry->args[0] = (long)filename;
    entry->args[1] = (long)flags;
    entry->args[2] = (long)mode;
}

void request_syscall_close(struct flexsc_sysentry *entry, unsigned int fd)
{
    entry->sysnum = __NR_close;
    entry->nargs = __ARGS_close;
    entry->rstatus = FLEXSC_STATUS_SUBMITTED;
    entry->args[0] = (long)fd;
}

void request_syscall_getpid(struct flexsc_sysentry *entry)
{
    entry->sysnum = __NR_getpid;
    entry->nargs = __ARGS_getpid;
}

/* long flexsc_getpid(struct flexsc_sysentry *entry)
{
    request_syscall_getpid(entry);
}

long flexsc_read(struct flexsc_sysentry *entry, unsigned int fd, char *buf, size_t count)
{
    request_syscall_read(entry, fd, buf, count);
}

long flexsc_write(struct flexsc_sysentry *entry, unsigned int fd, char *buf, size_t count) 
{
    request_syscall_write(entry, fd, buf, count);
}
 */
/* long flexsc_mmap(struct flexsc_sysentry *entry, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
    request_syscall_mmap(entry, addr, len, prot, flags, fd, pgoff);
} */

/* long flexsc_stat(struct flexsc_sysentry *entry); */
