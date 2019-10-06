Here are different versions of kernel code for flexSC.

Per-kthread means each kthread has its own sysentries, which means total sysentry here is 448 (per kthread has 64 entries, THIS IS CURRENTLY HARD-CODED).

It's recommended to use ../flexsc.c as base directory to modify *.[ch] files, since files here may outdated (e.g. `user_task->flexsc_enabled = 1` will no longer pass the compilation since the `task_struct` is modified).
