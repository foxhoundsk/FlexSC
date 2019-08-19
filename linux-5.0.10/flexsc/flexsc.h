#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>
#include <asm/syscall_wrapper.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/highmem.h>
#include <asm/cache.h>

#define FLEXSC "FlexSC: "

#define sys_mmap_pgoff ksys_mmap_pgoff
#define SYSTHREAD_NUM_MAX 1024
#define SYSTHREAD_NAME_MAX 20

#define FLEXSC_ERR_INIT_TGROUP_EMPTY 500
#define FLEXSC_ERR_INIT_COPY 501
#define FLEXSC_ERR_CACHE_LINE_MISMATCH 502
#define FLEXSC_ERR_CREATE_WQ 503
#define FLEXSC_ERR_CREATE_KTHREAD 504

#define FLEXSC_ALREADY_HOOKED 400
#define FLEXSC_ALREADY_NOT_HOOKED 401

#define FLEXSC_STATUS_FREE 0 
#define FLEXSC_STATUS_SUBMITTED 1
#define FLEXSC_STATUS_MARKED 2
#define FLEXSC_STATUS_DONE 3
#define FLEXSC_STATUS_BUSY 4

#define FLEXSC_PAGE_SIZE 4096

/* L1_CACHE_BYTES usually is 64 */
#define FLEXSC_ENTRY_SIZE L1_CACHE_BYTES

 /*
  * In my understanding, each syscall page should having only one sysentry,
  * as mentioned at section 3.2 of the paper (flawless0714)
  *
  * !Important 
  * FlexSC Configuration Options. We follow as the paper specify.
  * 8 System call pages per core, allowing up to 512 concurrent 
  * exception-less system calls per core.
  */
#define FLEXSC_MAX_SYSPAGE_PER_CPU 8
#define FLEXSC_MAX_ENTRY 64
#define FELXSC_MAX_CPUS 4

#define FLEXSC_MAX_HOOKED 100

#define SYSENTRY_NUM_DEFAULT 64

/* 
 * Maximum Pid default by 32768 
 * sysctl -w kernel.pid_max can change the maximum pid
 * */

#define FLEXSC_MAX_PID 8192
#define BITMAP_ENTRY 64

/**
 * @brief cache line size can be determined using in-kernel function
 */
#define FLEXSC_CACHE_LINE_SZIE 64

#define FLEXSC_WQ_NAME "FlexSC"
#define FLEXSC_KTHREAD_NAME "FlexSC_kthread"

struct flexsc_cpuinfo {
    int user_cpu;
    int kernel_cpu;
};


// asmlinkage void flexsc_syscall_hook(struct pt_regs *regs)
/**
 * @brief Define syscall entry. It should be same as cache line(64 bytes)
 */
struct flexsc_sysentry {
    unsigned nargs;
    unsigned rstatus;
    unsigned sysnum;
    unsigned sysret;
    long args[6];
} ____cacheline_aligned_in_smp;


struct flexsc_init_info {
    struct flexsc_sysentry **sysentry; /* Pointer to first sysentry */
    struct flexsc_cpuinfo cpuinfo;
    char *write_page; /* shared page for test write() */
    size_t npages; /* Number of Syspages */
    size_t nentry; /* # of workers should be equal to # of sysentries */
    size_t total_bytes;
};

/**
 * @brief syspage size should be 4KB(linux page size)
 */
struct flexsc_syspage {
    struct list_head flexsc_page_list; /* 8 bytes */
    struct flexsc_sysentry *entries[FLEXSC_MAX_ENTRY];
};

struct _kthread_list {
    struct task_struct *kthread_ts;
    int cpu;
    struct _kthread_list *next;
};
typedef struct _kthread_list kthread_list_t; 

struct k_handle_syspg_num {
    size_t start;
    size_t end;
};

void init_syspage(struct flexsc_syspage *);
void init_sysentry(struct flexsc_sysentry *);
void alloc_syspage(struct flexsc_syspage *);

void flexsc_start_hook(pid_t hooked_pid);
void flexsc_end_hook(pid_t hooked_pid);

int flexsc_enable_hook(void);
int flexsc_disable_hook(void);

void flexsc_map_syspage(void);
void flexsc_create_systhread_pool(void);
void flexsc_clone_systhread(void);  

void flexsc_destroy_workqueue(void);
void flexsc_free_works(void);

void * flexsc_mmap(size_t size, int locked, int *errp);
