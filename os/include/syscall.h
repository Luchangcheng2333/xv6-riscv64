#ifndef __SYSCALL_H
#define __SYSCALL_H

// System call numbers
#define SYS_fork 301
#define SYS_exit 302
#define SYS_wait 303
#define SYS_pipe 304
#define SYS_read 305
#define SYS_kill 306
#define SYS_exec 307
#define SYS_fstat 308
#define SYS_chdir 309
#define SYS_dup 310
#define SYS_getpid 311
#define SYS_sbrk 312
#define SYS_sleep 313
#define SYS_uptime 314
#define SYS_open 315
#define SYS_write 316
#define SYS_remove 317
#define SYS_trace 318
#define SYS_sysinfo 319
#define SYS_mkdir 320
#define SYS_close 321
#define SYS_test_proc 322
#define SYS_dev 323
#define SYS_dir 324
#define SYS_getcwd 325
//prebuilt syscalls

//new syscalls
#define SYS_lcc_getcwd 401
#define SYS_lcc_clone 402
#define SYS_lcc_getppid 403
#define SYS_lcc_openat 404
#define SYS_lcc_dup3 405
#define SYS_lcc_wait 406
#define SYS_lcc_mkdirat 407
#define SYS_lcc_yield 408
#define SYS_lcc_times 409
#define SYS_lcc_brk 410
#define SYS_lcc_uname 411
#define SYS_lcc_fstat 412
#define SYS_lcc_getdents 413
#define SYS_lcc_gettimeofday 414
#define SYS_lcc_mount 415
#define SYS_lcc_umount 416
#define SYS_lcc_mmap 417
#define SYS_lcc_munmap 418
#define SYS_lcc_unlink 419
#define SYS_lcc_sleep 420
#define SYS_lcc_getuid 421
#define SYS_lcc_geteuid 422
#define SYS_lcc_getgid 423
#define SYS_lcc_getegid 424
#define SYS_lcc_readlinkat 425
#define SYS_lcc_ioctl 426
#define SYS_lcc_rt_sigaction 427
#define SYS_lcc_getpgid 428
#define SYS_lcc_rt_sigprocmask 429
#define SYS_lcc_ppoll 430
#define SYS_lcc_fstatat 431
#define SYS_lcc_fcntl 432
#define SYS_lcc_sendfile 433
#define SYS_lcc_exitgroup 434

#endif