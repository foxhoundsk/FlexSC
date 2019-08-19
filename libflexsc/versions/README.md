Here are different versions of user code (library & measurement) of flexSC.

Per-kthread means each kthread has its own sysentries (in userland, user program has more sysentries than non_per_kthread one at same time), which means total sysentry here is 448 (per kthread has 64 entries, THIS IS CURRENTLY HARD-CODED).

Please make ../flexsc.c as base to modify *.c files here since files here may not the latest (e.g. `user_task->flexsc_enabled = 1` will no longer pass the compilation).