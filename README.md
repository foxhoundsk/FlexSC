# Implementation of FlexSC on Linux Kernel v5.0+ and Performance Analysis

## FlexSC
FlexSC (Flexible System Call), a mechanism to executing system call, which was introduced on [OSDI'10](https://www.usenix.org/conference/osdi10/flexsc-flexible-system-call-scheduling-exception-less-system-calls) by Livio Soares.

The main concept of FlexSC is processing syscalls in batching way, which has better cache locality and almost no CPU mode switch involved. For more details, the link above has link to the paper. Also, you can refer to my porting note at [HackMD](https://hackmd.io/@flawless0714/S1Wdf-g0V).

## How Syscall Being Processed by FlexSC
Syscalls are processed through the following steps:

1. The moment syscall being requested by user thread, it simply grab a free syscall entry, and submit (change the state of the entry) it after done population of syscall-related arguments to the entry
2. Once there are no free entries, the kernel visible thread start submitting (by marking syscall entry to different state) the entries to kthread
3. Kthread detects that it got stuff to do (by scanning syscall entries), then it start queuing work to the CMWQ workqueue
4. After the work (syscall) is done, kthread change the state of the syscall entry
5. Library of FlexSC (user space) detects that the syscall is done, it simply return the retval of the syscall to application thread

The following is the illustration of FlexSC:
```
        +---------------------------+
        |                           |
        |   user thread requesting  | .....
        |          syscalls         |
        |                           |
        +---------------------------+

        +---------------------------+
        |                           |
        |   kernel-visible thread   |
        |                           |                   +-----------+
        +---------------------------+                   |           |
                                        USER SPACE      |  shared   |
--------------------------------------------------------|  syscall  | .....
                                       KERNEL SPACE     |   entry   |
        +---------------------------+                   |           |
        |                           |                   +-----------+
        |   kthreads dispatching    |
        |  work to CMWQ workqueue   |
        |                           |
        +---------------------------+
```

## Implementation
The repo was originally downloaded from splasky/flexsc ([c69213](https://github.com/splasky/linux/tree/c69213aabcb1b6046ade5dbacfc95d1d0356ea14)), it was lacking many of implementation of FlexSC at that commit, and what I've implemented are the following:

- per-kthread syscall entries
- kernel-visible thread (pthread)
- performance measurement program (write() and getpid() syscall)
- func of kthread
- mechanism to get free syscall entry
- allocation of CMWQ workqueue and work

## Analysis
The following analysis are done with 7 kthreads (kernel cpu) and 1 kernel-visible thread (user cpu) on 8th-gen Intel CPU (i5-8350U) with HyperThreading enabled (4C8T).

- write() syscall:

    - Execution time:                 
    ![Screen](./libflexsc/perf_result/write.png)
    
    - Time elapsed for finding marked syscall entry (starts from the time the entry being marked as `FLEXSC_STATUS_MARKED`):
    ![Screen](./libflexsc/perf_result/find_marked_syspage_elapsed_time.png)

    - Time elapsed for library of FlexSC to find free syscall entry:
    ![Screen](./libflexsc/perf_result/get_free_syspage_elapsed_time.png)

    - Time elapsed for application thread to wait for completion of syscall after the library submitted syscall entry (marked as `FLEXSC_STATUS_SUBMITTED`:
    ![Screen](./libflexsc/perf_result/pthread_yield_elapsed_time.png)

    As you can see, the last result plays most part of the execution time. We use `pthread_yield()` to implement it, this is not a good practice, since application threads which is waiting on completion of requested syscall will keep checking if it has completed each time the time slice is dispatched to the thread.

    To addressing this issue, we can use `pthread_cond_wait()` and `pthread_cond_signal()` to make sure application threads are only wake up at completion of syscall. However, I've implemented a similar (a bit similar..) mechanism, even though it uses `pthread_cond_wait()`, but it uses `pthread_cond_broadcast()` to wake up application threads, which turns out has worser performance than `pthread_yield()` style implementation. Nevertheless, we can try using `pthread_cond_signal()` to implement a more efficient waiting mechanism.
        
    Summing analysis above, we might only optimize FlexSC to having similar result as typical syscall mechanism in the end, because processing syscall (write) in CMWQ costs ~500ns, summing it with other costs might lead to same consequence as I just mentioned.

- getpid() syscall:
    - Execution time:           
     ![Screen](./libflexsc/perf_result/getpid.png)

### Conclusion
It's been 10 years since FlexSC released, computer organization may changed a lot (e.g. [CPU mode switch in modern processor takes only <50ns within a round trip](https://i.imgur.com/bfgu0EK.png)). Therefore, even FlexSC doesn't has better performance than typical syscall, this is still a record which shows that imporvements of cache locality and mode switch can't still beats the time cost of typical syscall. Or, there exists some overheads within my implementation of FlexSC, feel free to open a issue if you find out anything. Thank you!

## Known Issues

- On exit of kthreads, oops and panic will occur. It's harmless to the test since the result is forced to flush before calling of exit of FlexSC.

## Acknowledgement
- @[afcidk](https://github.com/afcidk) - Discussing implementation of FlexSC
- @Livio Soares - Giving such concept to execute syscall
- @[splasky](https://github.com/splasky) - Providing prototype of FlexSC
- @[jserv](https://github.com/jserv) - Giving consultancy of FlexSC
