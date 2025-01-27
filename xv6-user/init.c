// init: The initial user-level program

#include "types.h"
#include "stat.h"
#include "file.h"
#include "fcntl.h"
#include "xv6-user/user.h"

char *argv[] = {"sh", 0};
char *args[] = {"./busybox", "sh", "busybox_testcode.sh"};

int main(void)
{
  int pid, wpid;

  // if(open("console", O_RDWR) < 0){
  //   mknod("console", CONSOLE, 0);
  //   open("console", O_RDWR);
  // }
  dev(O_RDWR, CONSOLE, 0);
  dup(0); // stdout
  dup(0); // stderr

  for (;;)
  {
    //printf("init: starting sh\n");
    pid = fork();
    if (pid < 0)
    {
      //printf("init: fork failed\n");
      exit(1);
    }
    if (pid == 0)
    {
      //exec("./busybox", args);

      exec("sh", argv);
      printf("init: exec sh failed\n");
      exit(1);
    }

    for (;;)
    {
      // this call to wait() returns if the shell exits,
      // or if a parentless process exits.
      wpid = wait((int *)0);
      if (wpid == pid)
      {
        // the shell exited; restart it.
        //break;
      }
      else if (wpid < 0)
      {
        //printf("init: wait returned an error\n");
        exit(1);
      }
      else
      {
        // it was a parentless process; do nothing.
      }
    }
  }
}
