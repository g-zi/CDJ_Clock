#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include "set_immediate_mode.h"

int
set_immediate_mode(int fd)
{
    int on = 1;
    return ioctl(fd, BIOCIMMEDIATE, &on);
    return 1;
}