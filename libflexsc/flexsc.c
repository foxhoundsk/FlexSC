/**
 * 
 * If syscall executed by FlexSC has wrong return value, you may need suspect that if this func need a 
 * memory barrier, since kthreads may start execution of syscall before user threads done population
 * (OOE) of syscall required argument.
 */

#include "flexsc.h"
#include <stdio.h>
#include <stdlib.h>

/* from the Linux kernel */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
/**
 * IF THE PERFORMANCE IS BAD, YOU MAY SUSPECT IF WE NEED TO PUT USER THREADS KEEP
 * WAITING ON PTREAD_COND INSTEAD OF BUSY WAITING FOR THE RESULT ONCE WOKEN UP BY
 * PTHREAD_BROADCAST.
 * 
 * Note that get_free_syscall_entry() should called with mutual lock to prevent
 * entry contention. Why not spinlock is that there may many threads waiting
 * on this lock, we should make them sleep 
 * 
 * syscall issue counter should implemented with spinlock, since ++ is a easy
 * work.
 * 
 * KERNEL CODE SHOULD SET A LIMIT FOR QUENTITY OF SYSPAGE, OR WE ARE CURRENTLY
 * LIMITED BY MEMORY ALLOCATION OF THE KERNEL (MORE SYSPAGE, MORE MEMORY REQUIRED).
 */

/**
 * WARN: this macro should equal to SYSENTRY_NUM_DEFAULT which defines at
 * ../flexsc.h. They are used to init same structure (sysentry). Since I'm
 * not sure the inclusion will work if I make this file and ../flexsc.c
 * including same file. This is also TODO
 */
#define SYSPAGE_PER_TASK /* do not greater than 64, which require memory over one PAGESIZE. We only impl mapping single PAGE currently */64

static void create_kv_thread(struct flexsc_init_info *info);
static inline int user_lock_init(void);
static void __flexsc_register(struct flexsc_init_info *info);
//static void flexsc_wait(void);

pthread_spinlock_t spin_free_entry, spin_user_pending;
pthread_cond_t user_wait = PTHREAD_COND_INITIALIZER;
pthread_mutex_t user_wait_cond = PTHREAD_MUTEX_INITIALIZER;

uint8_t syscall_runner = IDLE; /* this flag is set when user want syscalls to be executed or there has no free sysentry */

struct flexsc_init_info *u_info;

kv_thread_list_t kv_thread_list = {
    .tid = 0,
    .next = NULL,
};

static void __flexsc_register(struct flexsc_init_info *info) 
{
    printf("about to syscall flexsc_register (%s) with info addr: %p\n", __func__, info);
    syscall(SYSCALL_FLEXSC_REGISTER, info); 
}

/**
 * @brief worker of kernel-visible thread.
 * @Note we haven't done cleanup of this thread, since it's only created at init and terminated
 *       when about to exit, it's nothing to do with memory leak, so we leave the cleanup to
 *       the OS for now.
 */
static void *kv_thread_worker(void *arg)
{
    struct entry_carrier *target, *buf;

    while (1) {
        pthread_spin_lock(&spin_free_entry);

        if (likely(!list_empty(&u_info->busy_list)))
            list_for_each_entry_safe(target, buf, &u_info->busy_list, list) {
                if (FLEXSC_STATUS_SUBMITTED == target->entry->rstatus)
                    target->entry->rstatus = FLEXSC_STATUS_MARKED;
                else if (FLEXSC_STATUS_FREE == target->entry->rstatus) {
                    list_move(&target->list, &u_info->free_list);
                }
                
            }
        
        /* we should use pthread_cond_signal, which may save us more resources */
        //pthread_cond_broadcast(&user_wait);
/*
        while (!list_empty(&u_info->done_list))
            list_for_each_entry(target, &u_info->done_list, list)
                target->entry->rstatus = FLEXSC_STATUS_DONE;
  */      
        pthread_spin_unlock(&spin_free_entry);

        //pthread_cond_broadcast(&user_wait); needed if we use cond wait

        pthread_yield();
    }

    // unreachable, just to silence gcc warning
    pthread_exit(NULL);
}

/**
 * @brief Initialize which CPUs are pinned to user threads or kernel threads.
 * Default setting assumes 8 cores which has 4 cores enabled with Hyper threading.
 * But for measuring accurate result, Turing HT off is recommended.
 * @param cpuinfo
 */
static void init_cpuinfo_default(struct flexsc_cpuinfo *cpuinfo)
{
    //cpuinfo->user_cpu = FLEXSC_CPU_CLEAR;
    //cpuinfo->kernel_cpu = FLEXSC_CPU_CLEAR;

    /* we should use macro to do these stuff, which makes it easier to change the conf */
    cpuinfo->user_cpu = FLEXSC_CPU_0;
    cpuinfo->kernel_cpu =  FLEXSC_CPU_4 | FLEXSC_CPU_5 | FLEXSC_CPU_6 | FLEXSC_CPU_7 | FLEXSC_CPU_1 | FLEXSC_CPU_2 | FLEXSC_CPU_3;
}

static int init_user_affinity(struct flexsc_cpuinfo *ucpu)
{
    cpu_set_t user_set;
    int ucpus = ucpu->user_cpu;
    int cpu_no = 0;

    /* init */
    CPU_ZERO(&user_set);

    while (ucpus) {
        if (ucpus & 0x1) {
            CPU_SET(cpu_no, &user_set);
        }

        ucpus >>= 1;
        ++cpu_no;
    }

    if (-1 == sched_setaffinity(0, sizeof(cpu_set_t), &user_set)) {
        perror("sched_setaffinity failed");
        return FLEXSC_ERR_INIT;
    }

    return 0;
}

/* Prevent syspage from swapped out */
static int init_lock_syspage(struct flexsc_init_info *info)
{
    int error;

    if (!info->sysentry) {
        printf("info->sysentry is NULL at -->> %s\n", __func__);
        return -1;
    }
    
    error = mlock(info->sysentry, info->total_bytes); /* mlock treat unit of `len` as pages, which means we don't need to care redundant bytes */
    if (error) {
        printf("Failed to mlock `syspage` at -->> %s\n", __func__);
        return FLEXSC_ERR_LOCKSYSPAGE;
    }

    if (!info->write_page) {
        printf("info->sysentry is NULL at -->> %s\n", __func__);
        return -1;
    }

    error = mlock(info->write_page, 100000);
    if (error) {
        printf("Failed to mlock `syspage` at -->> %s\n", __func__);
        return FLEXSC_ERR_LOCKSYSPAGE;
    }

    return 0;
}

static int init_map_syspage(struct flexsc_init_info *info)
{
    size_t pgsize = getpagesize();

    size_t total = 7 /* # of kernel cpu */ * SYSPAGE_PER_TASK * (sizeof(struct flexsc_sysentry));
    struct flexsc_sysentry *entry;

    info->npages = SYSPAGE_PER_TASK * 7;

    /**
     * note that we don't init (except `rstatus`) or reset `sysentry`, since we has `entry->nargs`, which
     * inform the callee how many args we bring to him. As we has `entry->nargs`, we
     * will set array of args properly, so there is nothing to worry about.
     */
    entry = (struct flexsc_sysentry*) aligned_alloc(pgsize, total);
    if (!entry){
        perror("entry");
        return FLEXSC_ERR_INIT;
    }

    for (int i = 0; i < info->npages; i++) {
        entry[i].rstatus = FLEXSC_STATUS_FREE;
    }
    /* debug use */ entry[399].sysnum = 12345;
    printf("debug msg: done --%s-- at func -->> %s\n", "sysentry init", __func__);

    info->write_page = (char*) aligned_alloc(pgsize, 100000); /* 25 page needed (if pagesize = 4k) */
    if (!info->write_page) {
        puts("allocation for `write_page` failed");
        return FLEXSC_ERR_INIT;
    }

    info->nentry = SYSPAGE_PER_TASK;
    info->sysentry = entry;
    info->total_bytes = total;

    struct entry_carrier *carrier = aligned_alloc(pgsize, sizeof(struct entry_carrier) * info->npages);
    if (!carrier) {
        perror("carrier");
        return FLEXSC_ERR_INIT;
    }
    for (int i = 0; i < info->npages; i++) {
        carrier[i].entry = &entry[i];
        list_add(&carrier[i].list, &info->free_list);
    }

    return 0;
}

/**
 * Since init is a one-shot function, we don't use `likely` and `unlikely`
 * to increase rate of cache hit.
 */
static int init_info_default(struct flexsc_init_info *info) 
{
    /* Allocate syspage and map it to user space */
    if (init_map_syspage(info)) {
        goto err;
    }

    if (init_lock_syspage(info)) {
        goto err;    
    }

    init_cpuinfo_default(&(info->cpuinfo));

    /* set CPU affinity for user threads */
    init_user_affinity(&(info->cpuinfo));

    printf("debug msg: done --%s--\n", __func__);

    return 0;

    /**
     * currently, I leave allocated resource to be reclaimed by OS,
     * which is not a good practice, we should free them by ourself.
     */
err:
    return FLEXSC_ERR_INIT;
}

/* TODO: if user doesn't specified setting, we use default, otherwise we should use custom setting */
static int init_info(struct flexsc_init_info *info)
{
    return init_info_default(info);
}

void print_init_info(struct flexsc_init_info *info) 
{
    printf("flexsc_init_info\n");
    printf("number of sysentry: %ld\n", info->npages);
    printf("starting address of sysentry: %p\n", info->sysentry);
    printf("user cpu:%x, kernel cpu:%x\n", (info->cpuinfo).user_cpu, (info->cpuinfo).kernel_cpu);
    printf("npage: %ld\n", info->npages);
    printf("nentry: %ld\n", info->nentry);
    printf("total_bytes: %ld\n", info->total_bytes);
    printf("user pid: %d, ppid: %d\n", getpid(), getppid());
}

/**
 * @brief init flexSC-related stuff with given `info`, we are using our default info currently,
 * we should using the info from caller in the future.
 * @info init info from the user program.
 */
struct flexsc_init_info *
flexsc_register(struct flexsc_init_info *info)
{
    if (!info) {
        puts("NULL info pointer");
        return NULL;
    }

    u_info = info;

    INIT_LIST_HEAD(&u_info->free_list);
    INIT_LIST_HEAD(&u_info->busy_list);
    //INIT_LIST_HEAD(&u_info->done_list);

    printf("about to syscall with addr: %p (:%d)\n", u_info, __LINE__);

    if (FLEXSC_ERR_INIT == init_info(u_info))
        return NULL;
    
    print_init_info(u_info);
    printf("debug msg: done --%s--\n", __func__);
    printf("about to syscall with addr: %p (:%d)\n", u_info, __LINE__);

    create_kv_thread(u_info);
    printf("about to syscall with addr: %p (:%d)\n", u_info, __LINE__);

    if (FLEXSC_ERR_INIT == user_lock_init())
    /* TODO: cleanup should be impl (free(syspage...etc)) */
        return NULL;

    printf("about to syscall with addr: %p\n", u_info);
    __flexsc_register(u_info);
    
    return info;
}


long flexsc_exit(void)
{
    long ret;

    ret = syscall(SYSCALL_FLEXSC_EXIT);
    
    pthread_spin_destroy(&spin_free_entry);
    pthread_spin_destroy(&spin_user_pending);

    free(u_info->sysentry);
    free(u_info);

    return ret;
}

/*
static void flexsc_wait(void) 
{
    syscall(SYSCALL_FLEXSC_WAIT);
}
*/

/**
 * @brief create kernel-visible threads for per core.
 */
static void create_kv_thread(struct flexsc_init_info *info)
{
    kv_thread_list_t *kv_thread_tmp = &kv_thread_list;
    int idx;
    int ucpus = info->cpuinfo.user_cpu;
    int cpu_no = 0, cpu_qnt = 0;
    int part, remain, acc = 0;
    struct kv_handle_syspg_num *kv_handle_tmp;

    /* iterate user_cpu to get affinity for each kernel-visible thread */
    for (; ucpus; cpu_no++, ucpus >>= 1) {
        if (ucpus & 0x1) {
            CPU_ZERO(&(kv_thread_tmp->cpu));

            CPU_SET(cpu_no, &(kv_thread_tmp->cpu));
            cpu_qnt++;

            if (pthread_attr_init(&(kv_thread_tmp->t_attr))) {
                printf("pthread_attr_init failed, (%s)\n", __func__);
                exit(-1);
            }

            if (pthread_attr_setaffinity_np(&(kv_thread_tmp->t_attr), sizeof(cpu_set_t), &(kv_thread_tmp->cpu))) {
                printf("pthread_attr_setaffinity_np failed (%s)\n", __func__);
                exit(-1);
            }

            /* snoop for next cpu */
            if (ucpus >> 1) {
                kv_thread_tmp->next = (kv_thread_list_t*) malloc(sizeof(kv_thread_list_t));
                if (!kv_thread_tmp->next) {
                    printf("malloc failed at %s:%d\n", __func__, __LINE__);
                    exit(-1);
                }

                kv_thread_tmp = kv_thread_tmp->next;
            }

        }
    }
    
    part = info->npages / cpu_qnt;
    remain = info->npages % cpu_qnt;
    //kv_handle_tmp = (struct kv_handle_syspg_num*) malloc(sizeof(struct kv_handle_syspg_num) * cpu_qnt);
    /* due to glibc impl (2.28+), using memory allocated by malloc somehow cause error (malloc: invalid size (unsorted)). We use aligned_alloc() instead */
    kv_handle_tmp = (struct kv_handle_syspg_num*) aligned_alloc(getpagesize(), sizeof(struct kv_handle_syspg_num) * cpu_qnt); 
    printf("num of cpu_qnt: %d\n", cpu_qnt);
    for (idx = 0; idx < cpu_qnt; idx++) {
        kv_handle_tmp[idx].start = acc;
        acc += part;
        kv_handle_tmp[idx].end = acc - 1;
    }
    if (remain) {
        kv_handle_tmp[idx].end = (remain == 1) ? 1: remain - 1;
    }

    pthread_create(&(kv_thread_tmp->tid), NULL, kv_thread_worker, NULL);
/*
    for (idx = 0, kv_thread_tmp = &kv_thread_list;;) {
        printf("debug: start and end of idx of kv_thread is: %lu, %lu\n", kv_handle_tmp[idx].start, kv_handle_tmp[idx].end);

        pthread_create(&(kv_thread_tmp->tid), &(kv_thread_tmp->t_attr), kv_thread_worker, &kv_handle_tmp[idx]);
        if (++idx < cpu_qnt)
            kv_thread_tmp = kv_thread_tmp->next;
        else {
            kv_thread_tmp->next = NULL; // make sure last element has its `next` NULL
            break;
        }
    }
*/
}

static inline int user_lock_init(void)
{
    if (pthread_spin_init(&spin_free_entry, PTHREAD_PROCESS_PRIVATE))
        return FLEXSC_ERR_INIT;
    if (pthread_spin_init(&spin_user_pending, PTHREAD_PROCESS_PRIVATE))
        return FLEXSC_ERR_INIT;

    return 0;
}

/**
 * @brief force flexSC to process syscalls, upon return, all syspage is free
 * by DONE_CNT times of check with SCAN_INTERVAL_us as the scan interval.
 * 
 * note: this func is required if you have requested syscalls less than size
 * of syspage, or you just want flexSC to start processing your requested
 * syscalls. Besides, this is a busy waiting API currently (TODO).
 */
void flexsc_start_syscall(void)
{
    int done_cnt = 0;
    int idx;

    pthread_spin_lock(&spin_user_pending);
    syscall_runner = IN_PROGRESS;
    pthread_spin_unlock(&spin_user_pending);
    return;
retry:
    for (idx = 0; idx < u_info->npages; idx++) {
        if (u_info->sysentry[idx].rstatus != FLEXSC_STATUS_FREE) {
            //printf("status of not freed syspage: %u\n", u_info->sysentry[idx].rstatus);
            break;
        }
    }
    printf("flexsc_start_syscall scanning\n");
    if (idx == u_info->npages) {
        done_cnt++;
        if (done_cnt == DONE_CNT) {
            pthread_spin_lock(&spin_user_pending);
            syscall_runner = IDLE;
            pthread_spin_unlock(&spin_user_pending);
            
            return;
        }
    }
    else {
        if (done_cnt) {
            puts("\n\n\ndone_cnt != 0 \n\n");
        }

        done_cnt = 0;

        /* kv_threads thoughts all syspages is processed, they are wrong, here restart the execution */
        if (syscall_runner == DONE) {
            pthread_spin_lock(&spin_user_pending);
            syscall_runner = IN_PROGRESS;
            pthread_spin_unlock(&spin_user_pending);
        }
    }

    // pthread_yield(); too much intensive
    usleep(SCAN_INTERVAL_us);
    goto retry;
}
