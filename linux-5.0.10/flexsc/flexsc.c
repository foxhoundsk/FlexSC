/**
 * WARN TODO: on exit of kthread (calling do_flexsc_exit()), oops will occur on first try
 * to stop the kthread, and the kernel will subsequently crash. But if we have only one
 * kernel cpu to stop, it only cause oops, and the test program is still exit peacefully.
 * When occuring the former one problem, you can simply shutdown the QEMU since the test
 * result has already saved at this stage.
 * 
 * WARN: if syscall is depends on `current`, the result of execution may be faulty,
 * since the syscall is not executed instantly after filled into the syscall page.
 * there are two way to solve this:
 * 1. record the `current` info, once you are about to execute the corresponding syscall,
 * you use the saved `current` info.
 * 2. once detected the queued syscall is a `current`-dependent sysacll, execute it immediately.
 * This may cause penalty on performance, but correctness is more than performance. (and which
 * in turn means performing syscall with flexSC is meanless...)
 * 
 * WARN: Currently, implementation only allows single user program execute with flexsc, which
 * means more than one program executing with flexsc concurrently may result in undefined
 * behavior and has highly chance to crash the kernel.
 * 
 * TODO `SYSENTRY_NUM_DEFAULT` (flexsc/flexsc.c) and `SYSPAGE_PER_TASK` are
 * the same stuff. we should merge them to same macro. 
 * 
 * func `flexsc_wq_worker`: not sure if barrier is needed.
 * 
 * (08/13 update: haven't test performance on letting only one kernel cpu to scan the syscall
 * page, and the rest of kernel cpus only processing queued work (queue_work_on_cpu()). In
 * current implementation , all kernel cpus are scanning the syscall page and queueing work
 * on their own behalf (queue_work) ).
 * systhread_fn: was intend to use queue_work, but realize that if we use it, our work may
 * dispatched to the cpu executing kthread of flexSC which is busier than others, hence we
 * use another kernel cpu specified by the user program (or default cpu specified at lib).
 */

#include "flexsc.h"
#include <asm/syscall.h>
#include <asm/barrier.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/sched/task.h>

/* write() related */
#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>

#include <asm/thread_info.h>
#include <asm-generic/bug.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/sched/xacct.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/ioprio.h>
#include <linux/splice.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include "../fs/internal.h"

#include <linux/uaccess.h>
#include <asm/unistd.h>

static struct workqueue_struct *flexsc_workqueue;
static struct work_struct **flexsc_works;

static int systhread_fn(void *args);
static int create_workstruct(struct flexsc_init_info *info);
static int create_wq(void);
static void flexsc_wq_worker(struct work_struct *work);
static int create_kthread(struct flexsc_init_info *info);
static __always_inline long do_syscall(unsigned sysnum, struct pt_regs *regs);

struct task_struct *user_task;
struct task_struct *dispatcher_thread;
struct flexsc_init_info *k_info;
struct page **k_sysent_pg, **data_sh_pg;
struct k_handle_syspg_num *k_handle_syspg;
kthread_list_t kthread_list;
char **shared_pg;
struct file *shared_file;

/* change current to user_task which is user app executing flexSC */
#define flexsc_get_fs() (user_task->thread.addr_limit)
static inline void flexsc_set_fs(mm_segment_t fs)
{
	user_task->thread.addr_limit = fs;
	/* On user-mode return, check fs is correct */
	set_thread_flag(TIF_FSCHECK);
}

static inline int flexsc_get_current_ioprio(void)
{
	struct io_context *ioc = user_task->io_context;

	if (ioc)
		return ioc->ioprio;
	return IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);
}

static inline void flexsc_init_sync_kiocb(struct kiocb *kiocb, struct file *filp)
{
	*kiocb = (struct kiocb) {
		.ki_filp = filp,
		.ki_flags = iocb_flags(filp),
		.ki_hint = ki_hint_validate(file_write_hint(filp)),
		.ki_ioprio = flexsc_get_current_ioprio(),
	};
}

static ssize_t flexsc_new_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	flexsc_init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	iov_iter_init(&iter, WRITE, &iov, 1, len);

	ret = call_write_iter(filp, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0)
		*ppos = kiocb.ki_pos;
	return ret;
}

static ssize_t flexsc__vfs_write(struct file *file, const char __user *p, size_t count,
		    loff_t *pos)
{
	if (file->f_op->write)
		return file->f_op->write(file, p, count, pos);
	else if (file->f_op->write_iter)
		return flexsc_new_sync_write(file, p, count, pos);
	else
		return -EINVAL;
}

static ssize_t flexsc_vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	ret = rw_verify_area(WRITE, file, pos, count);
	if (!ret) {
		if (count > MAX_RW_COUNT)
			count =  MAX_RW_COUNT;
		file_start_write(file);
		ret = flexsc__vfs_write(file, buf, count, pos);
		if (ret > 0) {
			fsnotify_modify(file);
			add_wchar(user_task, ret);
		}
		inc_syscw(user_task);
		file_end_write(file);
	}

	return ret;
}

static struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = flexsc_get_fs();
    flexsc_set_fs(KERNEL_DS);

    ret = flexsc_vfs_write(file, data, size, &offset);

    flexsc_set_fs(oldfs);
    return ret;
}

static int create_kthread(struct flexsc_init_info *info)
{
    kthread_list_t *kthread_list_tmp = &kthread_list;
    int kcpus = k_info->cpuinfo.kernel_cpu;
    int idx;
    int cpu_no = 0, cpu_qnt = 0;
    int part, remain, acc = 0;

    kthread_list_tmp->next = NULL; /* clear previous usage of last application */

    /* iterate kernel_cpu to get affinity for each kthread */
    for (; kcpus; cpu_no++, kcpus >>= 1) {
        if (kcpus & 0x1) {
            kthread_list_tmp->cpu = cpu_no;

            cpu_qnt++;

            /* snoop for next cpu */
            if (kcpus >> 1) {
                kthread_list_tmp->next = (kthread_list_t*) kmalloc(sizeof(kthread_list_t), GFP_KERNEL);
                if (!kthread_list_tmp->next) {
                    printk(FLEXSC "kmalloc failed at %s:%d\n", __func__, __LINE__);
                    /* WARN: TODO: due to small chance to reach here, we haven't impl the cleanup (kfree allocated resources) */
                    goto err_mem_alloc;
                }

                kthread_list_tmp = kthread_list_tmp->next;
            }

        }
    }

    /* calculat syscall page handle area of each kthreads */
    part = info->npages / cpu_qnt;
    remain = info->npages % cpu_qnt;
    k_handle_syspg = (struct k_handle_syspg_num*) kmalloc(sizeof(struct k_handle_syspg_num) * cpu_qnt, GFP_KERNEL);
    if (unlikely(!k_handle_syspg)) {
        /* WARN: TODO: due to small chance to reach here, we haven't impl the cleanup (kfree allocated resources) */
        goto err_mem_alloc;
    }
    for (idx = 0; idx < cpu_qnt; idx++) {
        k_handle_syspg[idx].start = acc;
        acc += part;
        k_handle_syspg[idx].end = acc - 1;
    }
    if (remain) {
        k_handle_syspg[idx].end = (remain == 1) ? 1: remain - 1;
    }

    /* create kthread */
    for (idx = 0, kthread_list_tmp = &kthread_list;;) {
        //printk(FLEXSC "debug: start and size of kthread is: %lu, %lu\n", k_handle_syspg[idx].start, k_handle_syspg[idx].end);

        kthread_list_tmp->kthread_ts = kthread_create_on_cpu(systhread_fn, k_info->sysentry[idx], kthread_list_tmp->cpu, FLEXSC_KTHREAD_NAME".*%u");

        if (unlikely(!kthread_list_tmp->kthread_ts)) {
            printk(FLEXSC "kmalloc failed at %s:%d\n", __func__, __LINE__); // if entered, created kthreads should killed
            goto err_cret;
        }

        wake_up_process(kthread_list_tmp->kthread_ts);

        if (++idx < cpu_qnt) {
            kthread_list_tmp = kthread_list_tmp->next;
        }
        else {
            kthread_list_tmp->next = NULL; /* make sure last element has its `next` NULL */
            break;
        }
    }

    return 0;

err_cret:
err_mem_alloc:
    return FLEXSC_ERR_CREATE_KTHREAD;
}

/**
 * flexsc_wq_worker - worker of flexSC for CMWQ
 * 
 * @work: we have struct sysentry of flexsc embedded in `struct work_struct`,
 *        which make us can get particular syscall page from each work struct 
 */
static void flexsc_wq_worker(struct work_struct *work)
{
    //printk("FlexSC worker: processing queued work\n");

    // according to x86 syscall ABI
    work->regs->di = work->work_entry->args[0];
    work->regs->si = work->work_entry->args[1];
    work->regs->dx = work->work_entry->args[2];
    work->regs->r10 = work->work_entry->args[3];
    work->regs->r8 = work->work_entry->args[4];
    work->regs->r9 = work->work_entry->args[5];

    /* we let arg[0] as retval since sysentry->sysret has type unsigned, which can't fit into type long */
    //printk("FlexSC worker: start processing queued work\n");

    work->work_entry->args[0] = do_syscall(work->work_entry->sysnum, work->regs);
    //printk("FlexSC worker: done queued work (%ld)\n", work->work_entry->args[0]);

    /* AFTER TEST, PERFORMANCE IS BETTER (LITTLE) WITHOUT THIS, BUT CORRECTNESS IS UNKNOWN CURRENTLY
    ensure data are all committed before application start consume the result */
    //smp_mb();

    work->work_entry->rstatus = FLEXSC_STATUS_DONE;
       
    //printk("FlexSC worker: done single queued work, retval: %ld\n", work->work_entry->args[0]);
}

static int create_workstruct(struct flexsc_init_info *info)
{
    int i, x;
    ssize_t sz = sizeof(struct work_struct);
    ssize_t sz_ptregs = sizeof(struct pt_regs);
    struct pt_regs *sys_regs;

    flexsc_works = (struct work_struct**) kmalloc(sizeof(struct work_struct*) * 7, GFP_KERNEL);
    if (unlikely(!flexsc_works)) {
        printk(FLEXSC "workstruct allocation failed (allocatiopn of `struct work_struct*`)\n");
        return FLEXSC_ERR_CREATE_WQ;
    }
    for (i = 0; i < 7; i++) {
        flexsc_works[i] = (struct work_struct*) kmalloc((sizeof(struct work_struct) * 64), GFP_KERNEL);
        if (unlikely(!flexsc_works[i])) {
            printk(FLEXSC "workstruct allocation failed (allocatiopn of `struct work_struct`)\n");
            return FLEXSC_ERR_CREATE_WQ;
        }
    }    

    /** 
     * allocating memory here to improve cache locality for syscall handler, 
     * if we don't do so, they need to allocate these as local variable, which
     * is not a good practice of cache locality. 
     */
    sys_regs = (struct pt_regs*) kmalloc(sizeof(struct pt_regs) * info->npages, GFP_KERNEL);
    if (unlikely(!sys_regs)) {
        printk(FLEXSC "workstruct allocation failed (allocation of `struct pt_regs`)\n");
        return FLEXSC_ERR_CREATE_WQ;
    }

    for (i = 0; i < 7; i++) {
        /**
         * clear up of sysentry is not necessary as user populating
         * corresponding slots themself, and slots doesn't
         * populated are ignored by the syscall handler
         */
        for (x = 0; x < 64; x++) //(struct flexsc_sysentry*)((void*) info->sysentry[i] + (x * sz))
            //FLEXSC_INIT_WORK((struct work_struct*)((void*) flexsc_works[i] + (x * sz)), flexsc_wq_worker, info->sysentry[i] + x, (struct pt_regs*)((void*) sys_regs + (( /* head offset */i * sz_ptregs * 64) + (/* inner offset */x * sz_ptregs))));
            FLEXSC_INIT_WORK((struct work_struct*)((void*) flexsc_works[i] + (x * sz)), flexsc_wq_worker, info->sysentry[i] + x, sys_regs + (i * 64) + x);
    }

    return 0;
}

static int create_wq(void)
{
    /**
     *  not sure if WQ_CPU_INTENSIVE is needed since not sure if doing syscall is
     *  a intensive work (it may be simple (getpid) or hard (write() plenty of data))
     */
    if (!(flexsc_workqueue = alloc_workqueue(FLEXSC_WQ_NAME, WQ_HIGHPRI, 0)))
        return FLEXSC_ERR_CREATE_WQ;

    printk(FLEXSC "workqueue creation done successfully\n");

    return 0;    
}

static __always_inline long
do_syscall(unsigned sysnum, struct pt_regs *regs) {
    extern const sys_call_ptr_t sys_call_table[];

    long idx = regs->dx * 10;

    if (likely(sysnum == 1 /* __NR_write */)) 
        //return sys_call_table[sysnum](regs);
        return file_write(shared_file, 0, (char*) (shared_pg[(idx) / 4096] + idx), 10);

    printk(FLEXSC "wrong sysnum (%u)\n", sysnum);
    return -ENOSYS;
}

/* if we allocate syscall page from kernel, we don't need the parameter */
long do_flexsc_register(struct flexsc_init_info __user *info)
{
    /* debug */ // printk("address of sysentry received from user space: %p\n", info->sysentry);

    /* struct flexsc_sysentry *sysentry = info->sysentry; */
    int i;
    size_t pages;
    pid_t user_pid;
    long debug;

    user_pid = current->pid;

    /* this will be used to wake up process which is executing flexsc */
    user_task = current;

    printk(FLEXSC "addr of info (from user space): %p\n", info);

    k_info = (struct flexsc_init_info*) kmalloc(sizeof(struct flexsc_init_info), GFP_KERNEL);
    if (!k_info) {
        printk(FLEXSC "kmalloc for k_info failed\n");
        return -1L;
    }
    copy_from_user(k_info, info, sizeof(struct flexsc_init_info));
    printk(FLEXSC "addr of sysentry: %p\n", k_info->sysentry);

    data_sh_pg = (struct page**) kmalloc(sizeof(struct page*) * 25, GFP_KERNEL);
    shared_pg = (char**) kmalloc(sizeof(char*) * 25, GFP_KERNEL);
    for (i = 0; i < 25; i++)
        shared_pg[i] = NULL; /* reset for validation below */

    k_sysent_pg = (struct page**) kmalloc(7 * sizeof(struct page*), GFP_KERNEL);    

    // pages = (k_info->total_bytes % PAGE_SIZE) ? (k_info->total_bytes / PAGE_SIZE) + 1 : (k_info->total_bytes / PAGE_SIZE);
    pages = 7; /* if we want to map pages more than one page, we need to call kmap iteratively since it map one page at each call */
    down_read(&current->mm->mmap_sem);

    if (pages != (debug = get_user_pages((unsigned long) k_info->sysentry, pages, FOLL_WRITE, k_sysent_pg, NULL))) {
        printk(FLEXSC "failed at get_user_pages() (debug = %ld)\n", debug);
        return -1L;
    }

    pages = 25;
    if (pages != get_user_pages((unsigned long) k_info->write_page, pages, FOLL_WRITE, data_sh_pg, NULL)) {
        printk(FLEXSC "failed at get_user_pages() (data_sh_pg)\n");
        return -1L;
    }

    up_read(&current->mm->mmap_sem);

    k_info->sysentry = (struct flexsc_sysentry**) kmalloc(sizeof(struct flexsc_sysentry*) * 7, GFP_KERNEL);
    if (k_info->sysentry)
        printk(FLEXSC "kmap of k_sysentry done\n");
    else
        printk(FLEXSC "kmap of k_sysentry failed\n");
    for (i = 0; i < 7; i++)
        k_info->sysentry[i] = (struct flexsc_sysentry*) kmap(k_sysent_pg[i]);
    for (i = 0; i < 7; i++) {
        if (!k_info->sysentry[i]) {
            printk(FLEXSC "kmap of sysentry[i = %d] failed\n", i);
            return -1L;
        }
    }
    /*
    for (i = 0; i < 7; i++) {
        for (x = 0; x < 64; x++)
            printk(FLEXSC "sysentry->rstatus: %u\n", (k_info->sysentry[i] + x)->sysnum);
    }
      */  
    for (i = 0; i < 25; i++)
        shared_pg[i] = (char*) kmap(data_sh_pg[i]);

    if (k_info->sysentry)
        printk(FLEXSC "kmap of k_sysentry done\n");
    else
        printk(FLEXSC "kmap of k_sysentry failed\n");

    for (i = 0; i < 25; i++) {
        if (!shared_pg[i]) {
            printk(FLEXSC "kmap of shared_pg[i = %d] failed\n", i);
            return -1L;
        }
    }

    shared_file = file_open("/dev/null", O_WRONLY, 0);
    if (!shared_file) {
        printk(FLEXSC "open /dev/null failed\n");
        return -1L;
    }

    printk(FLEXSC "smp_processor_id(): %d\n", smp_processor_id());
    printk(FLEXSC "process(%d) calls flexsc_register\n", user_pid);
    printk(FLEXSC "number of entry: %ld\n", k_info->npages);

    if (FLEXSC_ERR_CREATE_WQ == create_wq()) {
        /* TODO WARN we should do cleanup related stuff */
        printk(FLEXSC "create workqueue failed!\n");
        return -1L;
    }
    printk(FLEXSC "create workqueue done\n");

    if (FLEXSC_ERR_CREATE_WQ == create_workstruct(k_info)) {
        /* TODO WARN we should do cleanup related stuff */
        printk(FLEXSC "create workstruct failed!\n");
        return -1L;
    }
    printk(FLEXSC "create workstruct done\n");
    
    if (FLEXSC_ERR_CREATE_KTHREAD == create_kthread(k_info)) {
        /* TODO WARN we should do cleanup related stuff, especially this one */
        printk(FLEXSC "create kthread failed!\n");
        return -1L;
    }
    printk(FLEXSC "create kthread done\n");
    /*
    smp_mb();
for (i = 0; i < 7; i++) {
        for (x = 0; x < 64; x++)
            printk(FLEXSC "sysentry->rstatus: %u\n", (k_info->sysentry[i] + x)->sysnum);
    }
    */
    printk(FLEXSC "flexsc_register syscall has done successfully\n");

    return 0L;
}

SYSCALL_DEFINE1(flexsc_register, struct flexsc_init_info *, info)
{	
	return do_flexsc_register(info);
}

long do_flexsc_exit(void)
{
    /**
     * lib of flexSC is responsible for freeing syscall page since
     * they allocate memory at user space.
     */

    kthread_list_t *kthread_list_tmp = &kthread_list, *kthread_list_next;

    printk(FLEXSC "%s\n", __func__);

    flush_scheduled_work();

    for (; kthread_list_tmp;) {
        kthread_list_next = kthread_list_tmp->next;
        printk(FLEXSC "debug: stopping kthread: %s\n", kthread_list_tmp->kthread_ts->comm);
        kthread_stop(kthread_list_tmp->kthread_ts);

        //smp_mb();
        kfree(kthread_list_tmp);

        kthread_list_tmp = kthread_list_next;

    }

    printk(FLEXSC "kthreads ARE ALL STOPPED\n");

    flexsc_destroy_workqueue();
    flexsc_free_works();
    return 0; // we are currently ignoring cleanup
    //kunmap(k_sysent_pg);

    if (k_info)
        kfree(k_info);
    else
        printk(FLEXSC "warning, k_info is empty\n");

    if (k_handle_syspg)
        kfree(k_handle_syspg);
    else
        printk(FLEXSC "warning, k_handle_syspg is empty\n");

    
    
    printk(FLEXSC "%s: cleanup done successfully\n", __func__);

    return 0;
}

SYSCALL_DEFINE0(flexsc_exit)
{	
	return do_flexsc_exit();
}

void flexsc_destroy_workqueue(void)
{
    if (!flexsc_workqueue) {
        printk(FLEXSC "WARN: flexsc workqueue is empty!\n");
        return;
    }

    printk(FLEXSC "Destroying flexsc workqueue...\n");
    destroy_workqueue(flexsc_workqueue);
}

void flexsc_free_works(void)
{
    if (!flexsc_works) {
        printk(FLEXSC "WARN: flexsc works is empty!\n");
        return;
    }

    printk(FLEXSC "Deallocating flexsc_works->regs...\n");    
    //kfree(flexsc_works->regs);

    printk(FLEXSC "Deallocating flexsc work structs...\n");
    //kfree(flexsc_works);
}

/**
 * @brief systhread checks a given systentry's status and chooses what to do
 * @param args pointer to struct flexsc_init_info, which used in kernel space
 * @ret N/A
 */
static int systhread_fn(void *args)
{
    struct flexsc_sysentry *syspage = (struct flexsc_sysentry*) args;
    int i;
    int cpu = smp_processor_id() - 1;
    int true_cpu = cpu + 1;
    struct work_struct *work = flexsc_works[cpu];
    printk(FLEXSC "kthread created! (cpu: %d)\n", cpu);
    //u32 cpu = 0;
    int sz = sizeof(struct work_struct);
    
    while (!kthread_should_stop()) {
        /* all kthreads iterating from 0 to npages has better performace than using interval scanning */
        for (i = 0; i < 64; i++) {
            //printk("syspage rstatus: %u, (#%d)\n", flexsc_info->sysentry[i].rstatus, i);
            //printk("scanning syspage (i: %d, cpu: %d, sysnum: %u, rstatus: %u)\n", i, true_cpu, work[i].work_entry->sysnum, syspage[i].rstatus);

            /* detect if syspage submitted, if it does, queue a work for the submitted syspage */
            if (FLEXSC_STATUS_MARKED == syspage[i].rstatus) {
                //syspage[i].rstatus = FLEXSC_STATUS_BUSY;
                //printk(FLEXSC "kthread processing syspage! (cpu: %d)\n", cpu);
                
                /* according to the doc of CMWQ, we guarantee that the work is queued to specific cpu in most case */
//                queue_work(flexsc_workqueue, (struct work_struct*) (((void*)flexsc_works[cpu]) + i * sz));
                //cpu = (cpu % 7) + 1; /* 1~7 */
                //printk("work queued (i: %d, cpu: %d)\n", i, true_cpu);
                //queue_work_on(true_cpu, flexsc_workqueue, &work[i]);
                //printk("work queued (i: %d, cpu: %d , sysnum: %u, rstatus: %u)\n", i, true_cpu, work[i].work_entry->sysnum, syspage[i].rstatus);

                queue_work(flexsc_workqueue, &work[i]);
            }
            /*
            else if (syspage[i].rstatus == 0xffffffff)
            {
                printk("\n\n\n\nsyspage 0xffffffff detected (i: %d, cpu: %d, rstatus: %u)\n\n\n\n", i, true_cpu, syspage[i].rstatus);

            }
            */            
        }
        
        schedule();
        //usleep_range(100, 100);
    }

    printk(FLEXSC "kthread about to stop...");

    do_exit(0);

    /* silence compiler warning */
    return 0;
}

/* THIS IS CURRENTLY NOT USED
Make calling thread (mostly user thread) sleep */
long do_flexsc_wait(void) 
{
    /* printk("Waking up sleeping systhread..."); */
    printk(FLEXSC "%d is going to sleep\n", current->pid);
    
    /* user thread goes to sleep */
    set_current_state(TASK_INTERRUPTIBLE);
    schedule();

    return 0L;
}

SYSCALL_DEFINE0(flexsc_wait)
{
	return do_flexsc_wait();
}

long do_flexsc_start_hook(pid_t hooked_pid) 
{
    printk("flexsc syscall version hook is here!\n");
    return 0;
}
EXPORT_SYMBOL_GPL(do_flexsc_start_hook);

SYSCALL_DEFINE1(flexsc_start_hook, pid_t, hooked_pid)
{	
	return do_flexsc_start_hook(hooked_pid);
}
