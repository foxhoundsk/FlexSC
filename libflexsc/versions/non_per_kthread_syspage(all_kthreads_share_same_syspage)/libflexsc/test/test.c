#include "flexsc.h"
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, const char *argv[])
{
    char buf[] = "Hello for hooking!";
    flexsc_register();
    flexsc_hook();
    flexsc_wait();

    sleep(2);


    gettid();
    write(1, buf, sizeof(buf));

    int fild = open("/proc/cpuinfo", O_RDONLY);


    return 0;
}
