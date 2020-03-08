#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

/* shmget series */
#include <sys/ipc.h>
#include <sys/shm.h>

#include "list.h"

#define SYSCALL_FLEXSC_REGISTER 400
#define SYSCALL_FLEXSC_EXIT 401

#define FLEXSC_STATUS_FREE 0 
#define FLEXSC_STATUS_SUBMITTED 1
#define FLEXSC_STATUS_MARKED 2
#define FLEXSC_STATUS_DONE 3
#define FLEXSC_STATUS_BUSY 4

#define FLEXSC_ERR_ALLOC 600
#define FLEXSC_ERR_LOCKSYSPAGE 601
#define FLEXSC_ERR_MAPSYSPAGE 602
#define FLEXSC_ERR_INIT 603

#define SYSENTRY_NUM_DEFAULT 128
struct flexsc_cpuinfo {
    int user_cpu;
    int kernel_cpu;
};

struct flexsc_cb {
    void (*callback) (struct flexsc_cb *);
    void *args;
    int64_t ret;
};


// 48(8 * 6) + 16(4 * 4) = 64 bytes
struct flexsc_sysentry {
    unsigned nargs;
    unsigned rstatus;
    unsigned sysnum;
    unsigned sysret;
    long args[6];
} ____cacheline_aligned_in_smp;

struct entry_carrier {
    struct list_head list;
    struct flexsc_sysentry *entry;
};

struct flexsc_init_info {
    struct flexsc_sysentry *sysentry; /* Pointer to first sysentry */
    struct list_head free_list;
    struct list_head busy_list;
    //struct list_head done_list;
    struct flexsc_cpuinfo cpuinfo; /* cpu bound info */
    char *write_page; /* shared page for test write() */
    size_t npages; /* Number of Syspages */
    size_t nentry; /* # of workers should be equal to # of sysentries */
    size_t total_bytes;
};
