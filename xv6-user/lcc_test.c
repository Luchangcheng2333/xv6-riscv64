// init: The initial user-level program

#include "types.h"
#include "stat.h"
#include "file.h"
#include "fcntl.h"
#include "xv6-user/user.h"

char *argv[] = {"sh", 0};

int main(void)
{
    int pid;

    // if(open("console", O_RDWR) < 0){
    //   mknod("console", CONSOLE, 0);
    //   open("console", O_RDWR);
    // }
    dev(O_RDWR, CONSOLE, 0);
    dup(0); // stdout
    dup(0); // stderr

    printf("init: starting test\n");
    pid = fork();
    if (pid < 0)
    {
        printf("init: fork failed\n");
        exit(1);
    }
    if (pid == 0)
    {
        exec("getpid", argv);
        if (!fork())
        {
            exec("/riscv64/fork", argv);
            exit(0);
        }
        else
            wait(0);
        if (!fork())
        {
            exec("/riscv64/dup2", argv);
            exit(0);
        }
        else
            wait(0);
        exit(0);
    }
    else
        wait(0);

    exit(0);
}
