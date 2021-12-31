#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "sysinfo.h"
#include "vm.h"
#include "printf.h"
#include "fcntl.h"
#include "fat32.h"
#include "string.h"
#include "defs.h"
#include "stat.h"
#include "sleeplock.h"
#include "file.h"
#include "fat32.h"
#include "debug.h"
#include "binformat.h"

extern struct proc proc[NPROC];

extern struct dirent *create(char *path, short type);
extern int fdalloc(struct file *f);
extern int argfd(int n, int *pfd, struct file **pf);
extern struct mappedfile * allocVma();
extern struct file *open(char *path, uint64 omode);

uint64 sys_lcc_getcwd(void);
uint64 sys_lcc_clone(void);
uint64 sys_lcc_getppid(void);
uint64 sys_lcc_openat(void);
uint64 sys_lcc_dup3(void);
uint64 sys_lcc_mkdirat(void);
uint64 sys_lcc_times(void);
uint64 sys_lcc_brk(void);
uint64 sys_lcc_uname(void);
uint64 sys_lcc_fstat(void);
uint64 sys_lcc_getdents(void);
uint64 sys_lcc_gettimeofday(void);
uint64 sys_lcc_mmap(void);
uint64 sys_lcc_munmap(void);
uint64 sys_lcc_unlink(void);
uint64 sys_lcc_sleep(void);
uint64 sys_lcc_getuid(void);
uint64 sys_lcc_geteuid(void);
uint64 sys_lcc_getgid(void);
uint64 sys_lcc_getegid(void);
uint64 sys_lcc_ioctl(void);
uint64 sys_lcc_tg_kill(void);
uint64 sys_lcc_readlinkat(void);
uint64 sys_lcc_rt_sigprocmask(void);
uint64 sys_lcc_rt_sigaction(void);
uint64 sys_lcc_ioctl(void);

/* Bits in the third argument to `waitpid'.  */
#define WNOHANG 1   /* Don't block waiting.  */
#define WUNTRACED 2 /* Report status of stopped children.  */

struct utsname
{
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct linux_dirent {
    uint64 d_ino;	// 索引结点号
    int64 d_off;	// 到下一个dirent的偏移
    unsigned short d_reclen;	// 当前dirent的长度
    unsigned char d_type;	// 文件类型
    char d_name[256];	//文件名
};

typedef struct
{
    uint64 sec;  // 自 Unix 纪元起的秒数
    uint64 usec; // 微秒数
} TimeVal;

struct kstat {
  uint64 st_dev;
  uint64 st_ino;
  mode_t st_mode;
  uint32 st_nlink;
  uint32 st_uid;
  uint32 st_gid;
  uint64 st_rdev;
  unsigned long __pad;
  off_t st_size;
  uint32 st_blksize;
  int __pad2;
  uint64 st_blocks;
  long st_atime_sec;
  long st_atime_nsec;
  long st_mtime_sec;
  long st_mtime_nsec;
  long st_ctime_sec;
  long st_ctime_nsec;
  unsigned __unused[2];
};


extern struct dirent root;

#define MAXMAPFILES 20

struct mt_list {
    struct dirent *origin_ep;
    struct dirent *target_ep;
};
struct mt_list *mount_list[MAXMAPFILES] = {0};

/* Data structure describing a polling request.  */
struct pollfd
{
  int       fd;      /* File descriptor to poll.  */
  short int events;  /* Types of events poller cares about.  */
  short int revents; /* Types of events that actually occurred.  */
};

/* Event types that can be polled for.  These bits may be set in `events'
   to indicate the interesting event types; they will appear in `revents'
   to indicate the status of the file descriptor.  */
#define POLLIN 01  /* There is data to read.  */
#define POLLPRI 02 /* There is urgent data to read.  */
#define POLLOUT 04 /* Writing now will not block.  */

/* these are defined by POSIX and also present in glibc's dirent.h */
#define DT_UNKNOWN  0
#define DT_FIFO   1
#define DT_CHR    2
#define DT_DIR    4
#define DT_BLK    6
#define DT_REG    8
#define DT_LNK    10
#define DT_SOCK   12
#define DT_WHT    14