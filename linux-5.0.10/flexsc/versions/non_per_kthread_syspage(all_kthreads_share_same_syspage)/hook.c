#include <linux/sched.h>
#include "flexsc.h"

static volatile long hook_enable = 0;
static volatile long hook_counts = 0;


asmlinkage void
flexsc_syscall_hook(unsigned long sysnum, const long args[])
{
    struct task_struct *task;
    /* unsigned long nr; */


    if (likely(!hook_enable)) {
        return;
    }

    task = current;

    if (likely(task->flexsc_enabled == 0)) {
        return;
    }


    /* if (likely(task->syspage == NULL)) {
        return;
    } */

    printk("Am I? %ld\n", sysnum);
    printk("sysnum %ld arg[0] %ld arg[1] %ld arg[2] %ld\n", 
            sysnum, args[0], args[1], args[2]);
    

    printk("syspage initialized\n");
    

    /* if (unlikely(!test_pid_bitmap(task->pid))) { */
        /* return; */

    /* } */

    printk("This process(%d) is hooked haha\n", task->pid);
    /* unsigned long nr = regs->orig_ax; */

    /* printk("hook[%4d]:[%5d] %3d "
           "%016lx %016lx %016lx %016lx %016lx %016lx\n",
           (int)(hook_counts++), task->pid, syscall_num, 
           args[0], args[1], args[2], args[3], args[4], args[5]); */
}


/*
 * Reference below site for xchg. It retruns the old value. 
 * http://lxr.free-electrons.com/source/arch/x86/include/asm/cmpxchg.h#L41 
 */

int flexsc_enable_hook()
{
    if (!xchg(&hook_enable, 1)) {
        printk("Enable flexsc hook!\n");
        return 0;
    }
    return FLEXSC_ALREADY_HOOKED;
}

int flexsc_disable_hook()
{
    if (xchg(&hook_enable, 0)) {
        printk("Disable FlexSC Hook!\n");
        return 0;
    }
    return FLEXSC_ALREADY_NOT_HOOKED;
}

void flexsc_start_hook(pid_t hooked_pid) 
{
    /* BUG_ON(hook_enable == 1); */
    /* set_pid_bitmap(hooked_pid); */
}

void flexsc_end_hook(pid_t hooked_pid)
{
    /* BUG_ON(hook_enable == 0); */
    /* clear_pid_bitmap(hooked_pid); */
}
