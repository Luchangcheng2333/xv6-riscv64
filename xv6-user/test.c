#include "types.h"
#include "stat.h"
#include "xv6-user/user.h"

#define O_RDONLY 0x000
#define O_WRONLY 0x001
#define O_RDWR 0x002
#define O_CREATE 0x040
#define O_TRUNC 0x200
#define O_DIRECTORY 0x200000

int main()
{
    int t = open("busybox_testcode.sh", O_RDWR);


    exit(0);
}
