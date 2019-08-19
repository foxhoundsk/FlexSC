# FlexSC Implementation on Linux Kernel v5.0+ and Performance Analysis

## FlexSC
FlexSC (Flexible System Call), a mechanism to executing system call, which was introduced on [OSDI'10](https://www.usenix.org/conference/osdi10/flexsc-flexible-system-call-scheduling-exception-less-system-calls) by Livio Soares.

The main concept of FlexSC is processing syscalls in batching way, which has better cache locality and almost no CPU mode switch involved. For more details, the link above has link to the paper. Also, you can refer to my porting note at [HackMD](https://hackmd.io/@flawless0714/S1Wdf-g0V).

## How Syscall Being Processed by FlexSC
Syscall are processed through the following steps:

1. The moment syscall being requested by user thread, it simply submit a syscall entry
2. Once there are no free entries, the kernel visible thread start submitting (by marking syscall entry to different state) the entries to kthread
3. kthread detects that it has stuff to do (by scanning syscall entries), then it start queuing work to CMWQ workqueue

The following is the illustration of FlexSC:
```
        |---------------------------|
        |                           |
        |   user thread requesting  | .....
        |          syscalls         |
        |                           |
        |---------------------------|

        |---------------------------|
        |                           |
        |   kernel visible thread   |
        |                           |                   |-----------|
        |---------------------------|                   |           |
                                        USER SPACE      |  shared   |
--------------------------------------------------------|  syscall  | .....
                                       KERNEL SPACE     |   entry   |
        |---------------------------|                   |           |
        |                           |                   |-----------|
        |   kthreads dispatching    |
        |  work to CMWQ workqueue   |
        |                           |
        |---------------------------|
```

## Implementation
The repo was originally downloaded from splasky/flexsc ([c69213](https://github.com/splasky/linux/tree/c69213aabcb1b6046ade5dbacfc95d1d0356ea14)), it was lacking many of implementation of FlexSC at that commit, and what I've implemented are the following:

- per-kthread syscall entries
- kernel visible thread (pthread)
- performance measurement program (write() and getpid() syscall)
- func of kthread
- mechanism to get free syscall entry
- allocation of CMWQ workqueue and work

## Analysis
TODO

## Acknowledgement
- @afcidk - discussing implementation of FlexSC
- @Livio Soares - giving such concepte to execute syscall
- @splasky - providing prototype of FlexSC
- @jserv - giving consultant of FlexSC
