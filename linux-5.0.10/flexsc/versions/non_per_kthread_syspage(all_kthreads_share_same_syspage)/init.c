#include "flexsc.h"

void init_flexsc_task(struct task_struct *ftask) 
{

}
void init_syspage(struct flexsc_syspage *syspage)
{
    /* int i; */
    /* Just for test */
    syspage = (struct flexsc_syspage *)kmalloc(sizeof(struct flexsc_syspage), GFP_KERNEL);




    /* for (i = 0; i < FLEXSC_MAX_ENTRY; i++) {
        init_sysentry(syspage->entry[i]);
    } */
}
void init_sysentry(struct flexsc_sysentry *sysentry)
{

}
