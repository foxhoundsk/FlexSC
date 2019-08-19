
#define __syscall_XX(sysnum, arg0, arg1, arg2, arg3, arg4, arg5) ({     \
            int __sysnum = (int)(sysnum);                               \
            register long __arg0 __asm__ ("rdi") = (long)(arg0);        \
            register long __arg1 __asm__ ("rsi") = (long)(arg1);        \
            register long __arg2 __asm__ ("rdx") = (long)(arg2);        \
            register long __arg3 __asm__ ("r10") = (long)(arg3);        \
            register long __arg4 __asm__ ("r8")  = (long)(arg4);        \
            register long __arg5 __asm__ ("r9")  = (long)(arg5);        \
                                                                        \
            long __ret;                                                 \
            asm volatile ("syscall"                             \
                                  : "=a" (__ret)                        \
                                  : "0" (__sysnum),                     \
                                    "r" (__arg0), "r" (__arg1),         \
                                    "r" (__arg2), "r" (__arg3),         \
                                    "r" (__arg4), "r" (__arg5)          \
                                  : "memory", "cc", "r11", "cx");       \
            __ret;                                                      \
        })

#define syscall6(sysnum, arg0, arg1, arg2, arg3, arg4, arg5)            \
    __syscall_XX(sysnum, arg0, arg1, arg2, arg3, arg4, arg5)
#define syscall5(sysnum, arg0, arg1, arg2, arg3, arg4)                  \
    __syscall_XX(sysnum, arg0, arg1, arg2, arg3, arg4, 0)
#define syscall4(sysnum, arg0, arg1, arg2, arg3)                        \
    __syscall_XX(sysnum, arg0, arg1, arg2, arg3, 0, 0)
#define syscall3(sysnum, arg0, arg1, arg2)                              \
    __syscall_XX(sysnum, arg0, arg1, arg2, 0, 0, 0)
#define syscall2(sysnum, arg0, arg1)                                    \
    __syscall_XX(sysnum, arg0, arg1, 0, 0, 0, 0)
#define syscall1(sysnum, arg0)                                          \
    __syscall_XX(sysnum, arg0, 0, 0, 0, 0, 0)
#define syscall0(sysnum)                                                \
    __syscall_XX(sysnum, 0, 0, 0, 0, 0, 0)
