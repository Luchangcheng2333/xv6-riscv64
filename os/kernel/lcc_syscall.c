#include "lcc_syscall.h"

uint64 sys_lcc_getcwd(void)
{
    int n;
    uint64 addr;

    struct dirent *de = myproc()->cwd;
    char path[MAXPATH];
    char *s;
    int len;

    if (argaddr(0, &addr) < 0 || argint(1, &n) < 0)
        return -1;

    if (de->parent == 0)
    {
        s = "/";
    }
    else
    {
        s = path + MAXPATH - 1;
        *s-- = '\0';
        while (de->parent)
        {
            len = strlen(de->filename);
            s -= len;
            if (s <= path) // can't reach root "/"
                return -1;
            strncpy(s, de->filename, len);
            *--s = '/';
            de = de->parent;
        }
    }

    if (addr != 0)
    {
        if (copyout(myproc()->pagetable, addr, s, strlen(s) + 1) < 0)
            return -1;
    }
    else 
    {
        addr = uvmalloc(myproc()->pagetable, myproc()->heap_addr, myproc()->heap_addr + n);
        if (copyout(myproc()->pagetable, 0, s, strlen(s) + 1) < 0)
            return -1;
    }

    return strlen(s);
}

uint64 sys_lcc_clone(void)
{
    int flag;
    uint64 stack_top;
    int new_pid;

    struct proc *p;

    if (argint(0, &flag) < 0 || argaddr(1, &stack_top) < 0)
        return -1;

    new_pid = fork();
    if (stack_top > 0)
    {
        for (p = proc; p < &proc[NPROC]; p++)
        {
            if (p->pid == new_pid)
                break;
        }
        p->trapframe->sp = stack_top; // change to the new sp
    }

    return new_pid;
}

uint64 sys_lcc_getppid(void)
{
    struct proc *current = myproc();
    return current->parent->pid;
}

uint64 sys_lcc_openat(void)
{
    int fd;
    char filename[FAT32_MAX_FILENAME + 1] = {0};
    int flags;
    int mode;

    struct file *f;
    struct dirent *ep;

    if (argint(0, &fd) < 0 || argstr(1, filename, FAT32_MAX_FILENAME + 1) < 0 ||
        argint(2, &flags) < 0 || argint(3, &mode) < 0)
        return -1;

    if (flags & O_CREATE)
    {
        ep = create(filename, T_FILE);
        if (ep == 0)
        {
            goto exists;
        }
    }
    else
    {
        exists:
        if ((ep = ename(filename)) == 0)
        {
            return -1;
        }
        elock(ep);
        /*
        if ((ep->attribute & ATTR_DIRECTORY) && flags != O_DIRECTORY)
        {
            eunlock(ep);
            eput(ep);
            return -1;
        }
        */
    }

    if ((f = filealloc()) == 0)
    {
        eunlock(ep);
        eput(ep);
        return -1;
    }

    f->type = FD_ENTRY;
    f->off = 0;
    f->ep = ep;
    f->readable = !(flags & O_WRONLY);
    f->writable = (flags & O_WRONLY) || (flags & O_RDWR); // set information

    if ((fd = fdalloc(f)) < 0)
    {
        eunlock(ep);
        fileclose(f);
        return -1;
    }

    eunlock(ep);

    return fd;
}

uint64 sys_lcc_dup3(void)
{
    int old_fd;
    int new_fd;
    struct file *f;
    struct proc *p;

    argint(0, &old_fd);
    argint(1, &new_fd);

    if (argfd(0, 0, &f) < 0)
        return -1;

    p = myproc();
    if (p->ofile[new_fd] != 0) // new_fd is already allocated
        return -1;

    p->ofile[new_fd] = f;
    filedup(f);

    return new_fd;
}

uint64 sys_lcc_wait(void)
{
    int pid;
    uint64 status;
    int options;

    if (argint(0, &pid) < 0 || argaddr(1, &status) < 0 || argint(2, &options) < 0)
        return -1;

    //printf("cpid is %d\n", pid);
    return wait(pid, status);
}

uint64 sys_lcc_mkdirat(void)
{
    int fd;
    char path[1024] = {0};
    int mode;
    struct dirent *ep;

    if (argint(0, &fd) < 0 || argstr(1, path, FAT32_MAX_FILENAME + 1) < 0 || argint(2, &mode) < 0)
        return -1;

    if ((ep = create(path, T_DIR)) == 0) // create directory
        return -1;

    eunlock(ep);
    eput(ep);
    return 0;
}

uint64 sys_lcc_yield(void)
{
    yield();
    return 0;
}

uint64 sys_lcc_times(void)
{
    uint64 addr;
    struct proc *current = myproc();
    struct tms time = *current->tms;

    if (argaddr(0, &addr) < 0)
        return -1;

    if (copyout(myproc()->pagetable, addr, (char *)&time, sizeof(time)) < 0)
        return -1;

    return 0;
}

uint64 sys_lcc_brk(void)
{
    uint64 addr;
    
    if (argaddr(0, &addr) < 0)
        return -1;

    uint64 oldsz = myproc()->heap_addr;
    if (addr == 0)
    {
        return oldsz;
    }
    else
    {
        if (growproc(addr - oldsz) < 0)
            return -1;
        return addr;
    }
}

uint64 sys_lcc_uname(void)
{
    uint64 addr;
    struct proc *current = myproc();

    if (argaddr(0, &addr) < 0)
        return -1;

    struct utsname uname =
        {"xv6-riscv", "linux-like", "5.8.0-59-generic", "#66~20.04.1-Ubuntu", "riscv64", "NIS domain name"};

    if (copyout(current->pagetable, addr, (char *)&uname, sizeof(uname)) < 0)
        return -1;

    return 0;
}

uint64 sys_lcc_fstat(void)
{
    uint64 addr = 0;
    int fd;
    struct file *f;
    struct proc *current = myproc();
    struct kstat *s = kalloc();

    if (argint(0, &fd) < 0)
        return -1;

    if (argfd(0, &fd, &f) < 0 || argaddr(1, &addr) < 0)
        return -1;

    memset(s, 0, sizeof(struct kstat));
    
    if (f->type == FD_DEVICE)
    {
        s->st_dev = 3;
        s->st_size = 0;
        s->st_nlink = 1;
        s->st_mode = 8624;
        s->st_blksize = 4096;
        s->st_blocks = 0;
        s->st_rdev = 1027;
        goto output;
    }

    s->st_uid = current->pid;
    if (f->ep != NULL)
    {
        s->st_size = f->ep->file_size;
        s->st_dev = f->ep->dev;
        s->st_nlink = f->ep->ref; // set information to definited struct
    }

    if ((f->ep->attribute & ATTR_DIRECTORY) != 0)
    {
        s->st_mode |= 0x4000;
    }
output:
    if (copyout(current->pagetable, addr, (char *)s, sizeof(struct kstat)) < 0)
        return -1;

    return 0;
}

// Read from dir f.
int
readdir(struct file *f, uint64 addr, int count)
{
  struct proc *p = myproc();

  if(f->readable == 0 || !(f->ep->attribute & ATTR_DIRECTORY)) {
    return -1;
  }
  
  int ret;
  uint64 old = addr;
  struct dirent de;
  struct linux_dirent d;
  for (;;) {
    elock(f->ep);
    while ((ret = enext(f->ep, &de, f->off, &count)) == 0) {
      // skip empty entry
      f->off += count * 32;
    }
    eunlock(f->ep);
    if (ret == -1) {
      /* meet the end of file */
      __debug_info("readdir", "meet end of file\n");
      return addr - old;
    }
    f->off += count * 32;
    /* TODO 
      d_ino maybe incorrect, though doensn't matter for simple "ls" 
    */
    d.d_ino = f->ep->first_clus;    
    d.d_off = f->off;
    memmove(d.d_name, de.filename, sizeof(de.filename));
    /* TODO 
      Here is different with Linux.
      Linux has a more compact memlayoutbut: different struct linux_dirent64 has different d_reclen.
      For convenience, I give every struct linux_dirent64 same d_reclen.
    */
    d.d_reclen = sizeof(d);
    d.d_type = (f->ep->attribute & ATTR_DIRECTORY) ? DT_DIR : DT_REG;
    /* every time copy out a struct linux_dirent64 */
    copyout(p->pagetable, addr, (char *)&d, sizeof(d));
    addr += sizeof(d);
  }
}

/* get directory entries */
uint64 sys_lcc_getdents(void)
{
  /* ssize_t getdents64(int fd, void *dirp, size_t count) */
  struct file *f;
  int count, fnum;
  uint64 addr; // user pointer to struct linux_dirent
  if(argfd(0, &fnum, &f) < 0 || argaddr(1, &addr) < 0 || argint(2, &count) < 0) {
    return -1;
  }
  return readdir(f, addr, count);
}


uint64 sys_lcc_gettimeofday(void)
{
    uint64 addr;
    TimeVal timer = {0, 0};
    uint64 time;

    if (argaddr(0, &addr) < 0)
        return -1;
    
    time = r_time();
    timer.sec = time / 32768;
    timer.usec = (time % 32768) * 1000000 / 32768;

    if (copyout(myproc()->pagetable, addr, (char *)&timer, 16) < 0)
        return -1;

    return 0;
}

uint64 sys_lcc_mount(void)
{
    char special[FAT32_MAX_FILENAME] = {0};
    char dir[FAT32_MAX_FILENAME] = {0};
    char ftype[FAT32_MAX_FILENAME] = {0};
    int flags;
    char data[FAT32_MAX_FILENAME] = {0};
    struct dirent *target_ep;
    struct dirent *origin_ep;
    char has_free_space = 0;

    if (argstr(0, special, FAT32_MAX_FILENAME + 1) < 0 || argstr(1, dir, FAT32_MAX_FILENAME + 1) < 0 || 
        argstr(2, ftype, FAT32_MAX_FILENAME + 1) < 0 || argint(3, &flags) < 0 || argstr(4, data, FAT32_MAX_FILENAME + 1) < 0)
        return -1;
    
    if ((origin_ep = ename(special)) == NULL) // find the original dev
    {
        origin_ep = &root; // no such device /dev/vda2, replace it with the root of the SD card
        //printf("Origin dev not found!\n");
        //return -1;
    }

    if ((target_ep = ename(dir)) == NULL || !(target_ep->attribute & ATTR_DIRECTORY)) // mount to dir is not only exist, but also a directory
    {
        printf("Target dir not found!\n");
        return -1;
    }

    elock(target_ep);
    elock(origin_ep);
    for (int i = 0; i < MAXMAPFILES; i++)
    {
        if (mount_list[i] == NULL)
        {
            has_free_space = 1; // found a free space
            if ((mount_list[i] = kalloc()) == NULL) // allocate memory first
            {
                printf("No free memory\n");
                return -1;
            }
            mount_list[i]->origin_ep = origin_ep;
            mount_list[i]->target_ep = target_ep; // build the relationship between device and target
            break;
        }
    }
    eunlock(origin_ep);
    eunlock(target_ep);

    if (has_free_space == 0)
    {
        printf("No free mount space\n");
        return -1;
    }

    return 0;
}

uint64 sys_lcc_umount(void)
{
    char special[FAT32_MAX_FILENAME] = {0};
    int flags;
    char is_mapfile_found = 0;
    struct dirent *ep;

    if (argstr(0, special, FAT32_MAX_FILENAME + 1) < 0 || argint(1, &flags) < 0)
        return -1;

    if ((ep = ename(special)) == NULL) // found target directory's dirent
    {
        printf("Target dir not found!\n");
        return -1;
    }

    for (int i = 0; i < MAXMAPFILES; i++)
    {
        if (mount_list[i] != NULL && (mount_list[i]->target_ep == ep || mount_list[i]->origin_ep == ep)) // found mount dir
        {
            is_mapfile_found = 1;
            kfree(mount_list[i]); // free space alloc before
            mount_list[i] = NULL;
        }
    }
    
    if (is_mapfile_found == 0)
    {
        printf("Such mount point not found\n");
        return -1;
    }

    return 0;
}

uint64 sys_lcc_mmap(void)
{
    uint64 start_addr;
    int size;
    int prot;
    int flags;
    int fd;
    int offset;
    struct file *f;
    struct proc *p = myproc();

    if (argaddr(0, &start_addr) < 0 || argint(1, &size) < 0 || argint(2, &prot) < 0 || argint(3, &flags) < 0 ||
        argfd(4, &fd, &f) < 0 || argint(5, &offset) < 0)
        return -1;

    #define MAP_ANONYMOUS 0x20
    if (flags & MAP_ANONYMOUS)
    {
        uint64 oldsz = p->heap_addr;
        if (growproc(size) < 0)
        {
            printf("[mmap] growproc error\n");
            return -1;
        }
        return oldsz;
    }

    // -- start_addr = p->trapframe->sp - (PGSIZE >> 1);
    start_addr = (uint64)kalloc();
    memset((void *)start_addr, 0, PGSIZE);
    mappages(myproc()->pagetable, start_addr, PGSIZE, start_addr, PTE_W | PTE_R | PTE_U | PTE_V);


    f->off = 0;
    if (fileread(f, start_addr, f->ep->file_size) == -1) // read the the address we found
    {
        printf("error in mmap\n");
        return -1;
    }
    
    for (int i = 0; i < NOFILE; i++)
    {
        if (p->map[i] == NULL)
        {
            struct mappedfile *m = kalloc();
            m->f = f;
            m->addr = start_addr;
            p->map[i] = m; // add file to map list
            break;
        }
        else if (i + 1 == NOFILE)
            return -1;
    }

    return start_addr;
}

uint64 sys_lcc_munmap(void)
{
    uint64 addr;
    int size;
    struct proc *p = myproc();

    if (argaddr(0, &addr) < 0 || argint(1, &size) < 0)
        return -1;

    for (int i = 0; i < NOFILE; i++)
    {
        if (p->map[i] != NULL && p->map[i]->addr == addr)
        {
            p->map[i]->f->off = 0; // reset the location
            filewrite(p->map[i]->f, addr, size); // write the data back to the file
            kfree(p->map[i]);
            uvmunmap(myproc()->pagetable, addr, 1, 0);
            kfree((void *)addr);
            break;
        }
        else if (i + 1 == NOFILE)
            return -1;
    }
    
    return 0;
}

uint64 sys_lcc_unlink(void)
{
    char *path = kalloc();
    if (argstr(1, path, FAT32_MAX_FILENAME + 1) < 0)
        return -1;

    struct dirent *ep = ename(path);
    etrunc(ep); // delete a file

    return 0;
}

uint64 sys_lcc_sleep(void)
{
    int time;
    uint64 addr;
    uint ticks0;
    TimeVal *tv = kalloc();

    if (argaddr(0, (uint64 *)&addr) < 0)
        return -1;

    if (copyin(myproc()->pagetable, (char *)tv, addr, 16) < 0)
        return -1;

    time = (tv->sec * 10 + (tv->usec + 9999) / 1000000); // calc the tick from time

    acquire(&tickslock);
    ticks0 = ticks;
    while (ticks - ticks0 < time)
    {
        if (myproc()->killed)
        {
            release(&tickslock);
            return -1;
        }
        sleep(&ticks, &tickslock);
    }
    release(&tickslock);

    return 0;
}

uint64 sys_lcc_getuid(void)
{
    //printf("sys_lcc_getuid -- called\n");
    return 0;
}

uint64 sys_lcc_geteuid(void)
{
    //printf("sys_lcc_geteuid -- called\n");
    return 0;
}

uint64 sys_lcc_getgid(void)
{
    //printf("sys_lcc_getgid -- called\n");
    return 0;
}

uint64 sys_lcc_getegid(void)
{
    //printf("sys_lcc_getegid -- called\n");
    return 0;
}

uint64 sys_lcc_ioctl(void)
{
  return 0;
}
uint64 sys_lcc_tg_kill(void)
{
  return 0;
}
uint64 sys_lcc_readlinkat(void)
{
  int        dirfd, n;
  char       filename[MAXPATH];
  const char s[] = "/busybox-musl";
  uint64 ubuf;
  if (argint(0, &dirfd) < 0 || argstr(1, filename, MAXPATH) < 0)
    return -1;
  if (argaddr(2, &ubuf) < 0 || argint(3, &n))
    return -1;
  //__debug_info("readlinkat", "buf addr = 0x%x\n", ubuf);
  if (copyout(myproc()->pagetable, ubuf, (char *)s, sizeof(s) + 1) < 0)
    return -1;
  return sizeof(s);
}

uint64 sys_lcc_rt_sigprocmask(void)
{
  return 0;
}

uint64 sys_lcc_rt_sigaction(void)
{
  return 0;
}

uint64 sys_lcc_getpgid(void)
{
    return 0;
}

uint64 sys_lcc_ppoll(void)
{
  struct pollfd fds[10];
  int           nfd;
  uint64      fds_addr;

  if (argaddr(0, &fds_addr) < 0 || argint(1, &nfd) < 0) {
    return -1;
  }
  if (nfd != 1) {
    printf("%d\n", nfd);
    panic("only support 1 pollfd");
  }

  if (copyin(myproc()->pagetable, (char *)fds, fds_addr,
             sizeof(struct pollfd) * nfd)) {
    return -1;
  }

  return 1;
}

uint64 sys_lcc_fstatat(void)
{
  int          dirfd;
  char         filepath[MAXPATH];
  struct kstat kst;
  uint64     kst_addr;
  if (argint(0, &dirfd) < 0 || argstr(1, filepath, MAXPATH) < 0 ||
      argaddr(2, &kst_addr) < 0) {
    return -1;
  }
  __debug_info("fstatat", "filename: %s\n", filepath);
  memset(&kst, 0, sizeof(struct kstat));
  
  struct file *f = open(filepath, O_RDONLY);
  if (f == NULL)
  {
      __debug_error("fstatat", "open file %s failed\n", filepath);
      return -1;
  }
  
  kst.st_dev = 1;
  kst.st_size = f->ep->file_size;
  kst.st_nlink = 1;
  if (f->ep->attribute & ATTR_DIRECTORY)
  {
      kst.st_mode = 16895;
  }
  else
  {
      kst.st_mode = 33279;
  }
  kst.st_gid = 0;
  kst.st_gid = 0;
  kst.st_uid = 0;
  kst.st_blksize = 4096;
  
  if (copyout(myproc()->pagetable, kst_addr, (char *)&kst,
              sizeof(struct kstat)) < 0) {
    return -1;
  }
  return 0;
}

uint64 sys_lcc_fcntl(void)
{
    return 0;
}

uint64 sys_lcc_sendfile(void)
{
    return -1;
}

uint64 sys_lcc_exitgroup(void)
{
    int n;
    if (argint(0, &n) < 0)
        return -1;
    exit(n);
    return 0;
}