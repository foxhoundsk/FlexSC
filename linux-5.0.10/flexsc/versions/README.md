Here are different versions of kernel code of flexSC.

Per-kthread means each kthread has its own sysentries, which means total sysentry here is 448 (per kthread has 64 entries, THIS IS CURRENTLY HARD-CODED).

Versions here may have some difference to ../flexsc.c, please make ../flexsc.c as base to modify *.c here since files here may not the latest (e.g. `user_task->flexsc_enabled = 1` will no longer pass the compilation).