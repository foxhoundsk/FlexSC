Here are different versions of user code (library & measurement) of flexSC.

Per-kthread means each kthread has its own sysentries (in userland, user program has more sysentries than non_per_kthread one at same time), which means total sysentry here is 448 (per kthread has 64 entries, THIS IS CURRENTLY HARD-CODED).

It's recommended to use `../` as base directory to modify *.[ch] files.
