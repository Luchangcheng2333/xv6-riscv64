
#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"
#include "sysinfo.h"

inline void change_syscall_num(int *num);

// Fetch the uint64 at addr from the current process.
int fetchaddr(uint64 addr, uint64 *ip)
{
  struct proc *p = myproc();
  if (addr >= p->heap_addr || addr + sizeof(uint64) > p->heap_addr)
    return -1;
  if (copyin(p->pagetable, (char *)ip, addr, sizeof(*ip)) != 0)
    return -1;
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Returns length of string, not including nul, or -1 for error.
int fetchstr(uint64 addr, char *buf, int max)
{
  struct proc *p = myproc();
  int err = copyinstr(p->pagetable, buf, addr, max);
  if (err < 0)
    return err;
  return strlen(buf);
}

static uint64
argraw(int n)
{
  struct proc *p = myproc();
  switch (n)
  {
  case 0:
    return p->trapframe->a0;
  case 1:
    return p->trapframe->a1;
  case 2:
    return p->trapframe->a2;
  case 3:
    return p->trapframe->a3;
  case 4:
    return p->trapframe->a4;
  case 5:
    return p->trapframe->a5;
  }
  panic("argraw");
  return -1;
}

// Fetch the nth 32-bit system call argument.
int argint(int n, int *ip)
{
  *ip = argraw(n);
  return 0;
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
int argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
  return 0;
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (including nul), -1 if error.
int argstr(int n, char *buf, int max)
{
  uint64 addr;
  if (argaddr(n, &addr) < 0)
    return -1;
  return fetchstr(addr, buf, max);
}

extern uint64 sys_chdir(void);
extern uint64 sys_close(void);
extern uint64 sys_dup(void);
extern uint64 sys_exec(void);
extern uint64 sys_exit(void);
extern uint64 sys_fork(void);
extern uint64 sys_fstat(void);
extern uint64 sys_getpid(void);
extern uint64 sys_kill(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_open(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_wait(void);
extern uint64 sys_write(void);
extern uint64 sys_uptime(void);
extern uint64 sys_test_proc(void);
extern uint64 sys_dev(void);
extern uint64 sys_dir(void);
extern uint64 sys_getcwd(void);
extern uint64 sys_remove(void);
extern uint64 sys_trace(void);
extern uint64 sys_sysinfo(void);

/*------ add by luchangcheng ------*/
extern uint64 sys_lcc_getcwd(void);
extern uint64 sys_lcc_clone(void);
extern uint64 sys_lcc_getppid(void);
extern uint64 sys_lcc_openat(void);
extern uint64 sys_lcc_dup3(void);
extern uint64 sys_lcc_wait(void);
extern uint64 sys_lcc_mkdirat(void);
extern uint64 sys_lcc_yield(void);
extern uint64 sys_lcc_times(void);
extern uint64 sys_lcc_brk(void);
extern uint64 sys_lcc_uname(void);
extern uint64 sys_lcc_fstat(void);
extern uint64 sys_lcc_getdents(void);
extern uint64 sys_lcc_gettimeofday(void);
extern uint64 sys_lcc_mount(void);
extern uint64 sys_lcc_umount(void);
extern uint64 sys_lcc_mmap(void);
extern uint64 sys_lcc_munmap(void);
extern uint64 sys_lcc_unlink(void);
extern uint64 sys_lcc_sleep(void);
extern uint64 sys_lcc_getuid(void);
extern uint64 sys_lcc_geteuid(void);
extern uint64 sys_lcc_getgid(void);
extern uint64 sys_lcc_getegid(void);
extern uint64 sys_lcc_readlinkat(void);
extern uint64 sys_lcc_ioctl(void);
extern uint64 sys_lcc_rt_sigprocmask(void);
extern uint64 sys_lcc_rt_sigaction(void);
extern uint64 sys_lcc_getpgid(void);
extern uint64 sys_lcc_ppoll(void);
extern uint64 sys_lcc_fstatat(void);
extern uint64 sys_lcc_sendfile(void);
extern uint64 sys_lcc_fcntl(void);
extern uint64 sys_lcc_exitgroup(void);

/*---------------------------------*/

static uint64 (*syscalls[])(void) = {
    [SYS_fork] sys_fork,
    [SYS_exit] sys_exit,
    [SYS_wait] sys_wait,
    [SYS_pipe] sys_pipe,
    [SYS_read] sys_read,
    [SYS_kill] sys_kill,
    [SYS_exec] sys_exec,
    [SYS_fstat] sys_fstat,
    [SYS_chdir] sys_chdir,
    [SYS_dup] sys_dup,
    [SYS_getpid] sys_getpid,
    [SYS_sbrk] sys_sbrk,
    [SYS_sleep] sys_sleep,
    [SYS_uptime] sys_uptime,
    [SYS_open] sys_open,
    [SYS_write] sys_write,
    [SYS_mkdir] sys_mkdir,
    [SYS_close] sys_close,
    [SYS_test_proc] sys_test_proc,
    [SYS_dev] sys_dev,
    [SYS_dir] sys_dir,
    [SYS_getcwd] sys_getcwd,
    [SYS_remove] sys_remove,
    [SYS_trace] sys_trace,
    [SYS_sysinfo] sys_sysinfo,

    /*-------- add by luchangcheng ---------*/
    [SYS_lcc_getcwd] sys_lcc_getcwd,
    [SYS_lcc_clone] sys_lcc_clone,
    [SYS_lcc_getppid] sys_lcc_getppid,
    [SYS_lcc_openat] sys_lcc_openat,
    [SYS_lcc_dup3] sys_lcc_dup3,
    [SYS_lcc_wait] sys_lcc_wait,
    [SYS_lcc_mkdirat] sys_lcc_mkdirat,
    [SYS_lcc_yield] sys_lcc_yield,
    [SYS_lcc_times] sys_lcc_times,
    [SYS_lcc_brk] sys_lcc_brk,
    [SYS_lcc_uname] sys_lcc_uname,
    [SYS_lcc_fstat] sys_lcc_fstat,
    [SYS_lcc_getdents] sys_lcc_getdents,
    [SYS_lcc_gettimeofday] sys_lcc_gettimeofday,
    [SYS_lcc_mount] sys_lcc_mount,
    [SYS_lcc_umount] sys_lcc_umount,
    [SYS_lcc_mmap] sys_lcc_mmap,
    [SYS_lcc_munmap] sys_lcc_munmap,
    [SYS_lcc_unlink] sys_lcc_unlink,
    [SYS_lcc_sleep] sys_lcc_sleep,
    [SYS_lcc_getuid] sys_lcc_getuid,
    [SYS_lcc_geteuid] sys_lcc_geteuid,
    [SYS_lcc_getgid] sys_lcc_getgid,
    [SYS_lcc_getegid] sys_lcc_getegid,
    [SYS_lcc_readlinkat] sys_lcc_readlinkat,
    [SYS_lcc_ioctl] sys_lcc_ioctl,
    [SYS_lcc_rt_sigaction] sys_lcc_rt_sigaction,
    [SYS_lcc_rt_sigprocmask] sys_lcc_rt_sigprocmask,
    [SYS_lcc_getpgid] sys_lcc_getpgid,
    [SYS_lcc_ppoll] sys_lcc_ppoll,
    [SYS_lcc_fstatat] sys_lcc_fstatat,
    [SYS_lcc_sendfile] sys_lcc_sendfile,
    [SYS_lcc_fcntl] sys_lcc_fcntl,
    [SYS_lcc_exitgroup] sys_lcc_exitgroup,
};  

void syscall(void)
{
  static char *sysnames[] = {
      [SYS_fork] "fork",
      [SYS_exit] "exit",
      [SYS_wait] "wait",
      [SYS_pipe] "pipe",
      [SYS_read] "read",
      [SYS_kill] "kill",
      [SYS_exec] "exec",
      [SYS_fstat] "fstat",
      [SYS_chdir] "chdir",
      [SYS_dup] "dup",
      [SYS_getpid] "getpid",
      [SYS_sbrk] "sbrk",
      [SYS_sleep] "sleep",
      [SYS_uptime] "uptime",
      [SYS_open] "open",
      [SYS_write] "write",
      [SYS_mkdir] "mkdir",
      [SYS_close] "close",
      [SYS_test_proc] "test_proc",
      [SYS_dev] "dev",
      [SYS_dir] "dir",
      [SYS_getcwd] "getcwd",
      [SYS_remove] "remove",
      [SYS_trace] "trace",
      [SYS_sysinfo] "sysinfo",

      /*-------- add by luchangcheng ---------*/
      [SYS_lcc_getcwd] "lcc_getcwd",
      [SYS_lcc_clone] "lcc_clone",
      [SYS_lcc_getppid] "lcc_getppid",
      [SYS_lcc_openat] "lcc_openat",
      [SYS_lcc_dup3] "lcc_dup3",
      [SYS_lcc_wait] "lcc_wait",
      [SYS_lcc_mkdirat] "lcc_mkdirat",
      [SYS_lcc_yield] "lcc_yield",
      [SYS_lcc_times] "lcc_times",
      [SYS_lcc_brk] "lcc_brk",
      [SYS_lcc_uname] "lcc_uname",
      [SYS_lcc_fstat] "lcc_fstat",
      [SYS_lcc_getdents] "lcc_getdents",
      [SYS_lcc_gettimeofday] "lcc_gettimeofday",
      [SYS_lcc_mount] "lcc_mount",
      [SYS_lcc_umount] "lcc_umount",
      [SYS_lcc_mmap] "lcc_mmap",
      [SYS_lcc_munmap] "lcc_munmap",
      [SYS_lcc_unlink] "lcc_unlink",
      [SYS_lcc_sleep] "lcc_sleep",
      [SYS_lcc_getuid] "lcc_getuid",
      [SYS_lcc_geteuid] "lcc_geteuid",
      [SYS_lcc_getgid] "lcc_getgid",
      [SYS_lcc_getegid] "lcc_getegid",
      [SYS_lcc_readlinkat] "lcc_readlinkat",
      [SYS_lcc_ioctl] "lcc_ioctl",
      [SYS_lcc_rt_sigaction] "lcc_rt_sigaction",
      [SYS_lcc_rt_sigprocmask] "lcc_rt_sigprocmask",
      [SYS_lcc_getpgid] "lcc_getpgid",
      [SYS_lcc_ppoll] "lcc_ppoll",
      [SYS_lcc_fstatat] "lcc_fstatat",
      [SYS_lcc_sendfile] "lcc_sendfile",
      [SYS_lcc_fcntl] "lcc_fcntl",
      [SYS_lcc_exitgroup] "lcc_exitgroup",

  };
  int num;
  struct proc *p = myproc();

  num = p->trapframe->a7;
  change_syscall_num(&num);

  if (num > 0 && num < NELEM(syscalls) && syscalls[num])
  {
    
    uint64 ret = 0;
    if (num != SYS_write && num != SYS_dir && num != SYS_read)
    {
      ret = syscalls[num]();
      p->trapframe->a0 = ret;
      #ifdef READSYSCALL
      struct trapframe *tf = p->trapframe;
      printf("syscall -- %s(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x), return 0x%x\n", 
        sysnames[num], tf->a0, tf->a1, tf->a2, tf->a3, tf->a4, tf->a5, ret);
      #endif
    }
    else
    {
      p->trapframe->a0 = syscalls[num]();
    }
    // trace
    if ((p->tmask & (1 << num)) != 0)
    {
      printf("pid %d: syscall %s -> %d\n", p->pid, sysnames[num], p->trapframe->a0);
    }
  }
  else
  {
    printf("pid %d %s: unknown sys call %d\n",
           p->pid, p->name, num);
    p->trapframe->a0 = 0;
  }
}

uint64
sys_test_proc(void)
{
  int n;
  argint(0, &n);
  printf("hello world from proc %d, hart %d, arg %d\n", myproc()->pid, r_tp(), n);
  return 0;
}

uint64
sys_sysinfo(void)
{
  uint64 addr;
  struct proc *p = myproc();

  if (argaddr(0, &addr) < 0)
  {
    return -1;
  }

  struct sysinfo info;
  info.freemem = freemem_amount();
  info.nproc = procnum();

  if (copyout(p->pagetable, addr, (char *)&info, sizeof(info)) < 0)
  {
    return -1;
  }

  return 0;
}

/*-------------------------- add by luchangcheng below -----------------------------------*/
inline void change_syscall_num(int *num)
{
  switch (*num)
  {
  case 64:
    *num = 316; //write, success
    break;
  case 93:
    *num = 302; //exit, success
    break;
  case 49:
    *num = 309; //chdir, success
    break;
  case 57:
    *num = 321; //close, success
    break;
  case 17:
    *num = 401; //getcwd, success
    break;
  case 172:
    *num = 311; //getpid, success
    break;
  case 260:
    *num = 406; //wait, waitpid, success
    break;
  case 34:
    *num = 407; //mkdirat, success
    break;
  case 63:
    *num = 305; //read, success
    break;
  case 56:
    *num = 404; //openat, success
    break;
  case 23:
    *num = 310; //dup, success
    break;
  case 59:
    *num = 304; //pipe, question
    break;
  case 220:
    *num = 402; //clone, success
    break;
  case 221:
    *num = 307; //execve, success
    break;
  case 173:
    *num = 403; //getppid, success
    break;
  case 24:
    *num = 405; //dup3, success
    break;
  case 80:
    *num = 412; //fstat, success
    break;
  case 101:
    *num = 420; //nanosleep, question
    break;
  case 124:
    *num = 408; //yield, question
    break;
  case 153:
    *num = 409; //times, question
    break;
  case 214:
    *num = 410; //brk
    break;
  case 160:
    *num = 411; //uname, success
    break;
  case 61:
    *num = 413; //getdents
    break;
  case 169:
    *num = 414; //gettimeofady
    break;
  case 39:
    *num = 416; // umount2
    break;
  case 40:
    *num = 415; // mount
    break;
  case 222:
    *num = 417; // mmap
    break;
  case 215:
    *num = 418; // munmap
    break;
  case 35:
    *num = 419; // unlinkat
    break;
  case 174:
    *num = 421; // getuid
    break;
  case 175:
    *num = 422; // geteuid
    break;
  case 176:
    *num = 423; // getgid
    break;
  case 177:
    *num = 424; // getegid
    break;
  case 78:
    *num = 425; // readlinkat
    break;
  case 29:
    *num = 426; // ioctl
    break;
  case 135:
    *num = 429; // rt_sigprocmask
    break;
  case 134:
    *num = 427; // rt_sigaction
    break;
  case 155:
    *num = 428; // getpgid
    break;
  case 73:
    *num = 430; // ppoll
    break;
  case 79:
    *num = 431; // fstatat
    break;
  case 25:
    *num = 432; // fcntl
    break;
  case 71:
    *num = 433; // sendfile
    break;
  case 94:
    *num = 434; // exit_group
    break;
  default:
    break;
  }
}
