struct stat;
struct rtcdate;
struct sysinfo;

// system calls
typedef unsigned int uint;
typedef unsigned long uint64;

int fork(void);
int exit(int) __attribute__((noreturn));
int wait(int *);
int pipe(int *);
int write(int, const void *, int);
int read(int, void *, int);
int close(int);
int kill(int);
int exec(char *, char **);
int open(const char *, int);
int fstat(int fd, struct stat *);
int mkdir(const char *);
int chdir(const char *);
int dup(int);
int getpid(void);
char *sbrk(int);
int sleep(int);
int uptime(void);
int test_proc(int);
int dev(int, short, short);
int dir(int fd, struct stat *);
int getcwd(char *);
int remove(char *);
int trace(int);
int sysinfo(struct sysinfo *);

// ulib.c
int stat(const char *, struct stat *);
char *strcpy(char *, const char *);
char *strcat(char *, const char *);
void *memmove(void *, const void *, int);
char *strchr(const char *, char c);
int strcmp(const char *, const char *);
void fprintf(int, const char *, ...);
void printf(const char *, ...);
char *gets(char *, int max);
uint strlen(const char *);
void *memset(void *, int, uint);
void *malloc(uint);
void free(void *);
int atoi(const char *);
int memcmp(const void *, const void *, uint);
void *memcpy(void *, const void *, uint);

//lcc_syscall.c
char *lcc_getcwd(char *buf, uint64 size);
int lcc_clone(uint64 clone_flags, uint64 new_stack, int parent_pid, int tls_val, int child_pid);
int lcc_getppid();
int lcc_openat(int fd, char *filename, int flags, int mode);
int lcc_dup3(int old_fd, int new_fd);
int lcc_mkdirat(int fd, char *path, int mode);
int lcc_brk(uint64 brk);
