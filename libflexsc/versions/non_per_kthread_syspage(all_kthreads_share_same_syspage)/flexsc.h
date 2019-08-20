/* Copyright (C) 
 * 2017 - Yongrae Jo
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * 
 */
#ifndef FLEXSC_H
#define FLEXSC_H

#define _GNU_SOURCE

#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdint.h>
#include <sched.h>
#include <stdio.h>
#include <sys/stat.h>
#include "flexsc_cpu.h"
#include "flexsc_types.h"
#include "syscall_info.h"

/* we use these flags to determine if syscall need handled */
#define IDLE 1
#define IN_PROGRESS 2
#define DONE 3

/* if reached, we consider requested syscalls are all done */
#define DONE_CNT 3

/* sleep time of scan interval of syspage (in microsecond) */
#define SCAN_INTERVAL_us (5 * 10e5)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

struct flexsc_init_info *flexsc_register(struct flexsc_init_info *info);
void flexsc_start_syscall(void);

/* we start processing syscall either running out of syscall page or call of this func */
void flex_start_syscall(void); 

void flexsc_hook(void);

pid_t gettid(void);

long flexsc_exit(void);

/**
 * @brief kernel visible user threads (per core correspondes to a single kv_thread)
 * @member tid id of single user thread
 * @member next address of next thread element
 * @note as it's impossible that there is no one threads exist, we don't using other
 * member to indicate if tid is valid.
 */
struct _kv_thread_list {
    pthread_t tid;
    cpu_set_t cpu;
    pthread_attr_t t_attr;
    struct _kv_thread_list *next;
};
typedef struct _kv_thread_list kv_thread_list_t;

/**
 * @brief each kernel-visible thread has its handle area of syscall page (utilizing benifit of concurrency)
 */
struct kv_handle_syspg_num {
    size_t start;
    size_t end;
};

#endif
