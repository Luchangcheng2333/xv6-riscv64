// Copyright (c) 2006-2019 Frans Kaashoek, Robert Morris, Russ Cox,
//                         Massachusetts Institute of Technology

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "defs.h"
#include "sbi.h"
#include "sdcard.h"
#include "fpioa.h"
#include "dmac.h"
#include "proc.h"
#include "rtc.h"

static inline void inithartid(unsigned long hartid)
{
  asm volatile("mv tp, %0"
               :
               : "r"(hartid & 0x1));
}

volatile static int started = 0;

void main(unsigned long hartid, unsigned long dtb_pa)
{
  inithartid(hartid);

  if (hartid == 0)
  {
    consoleinit();
    printfinit(); // init a lock for printf
    print_logo();
#ifdef DEBUG
    printf("hart %d enter main()...\n", hartid);
#endif
    kinit();        // physical page allocator
    kvminit();      // create kernel page table
    kvminithart();  // turn on paging
    trapinit();     // trap vectors
    trapinithart(); // install kernel trap vector
    timerinit();    // set up timer interrupt handler
    procinit();
    plicinit();
    plicinithart();
#ifndef QEMU
    fpioa_pin_init();
    dmac_init();

    // add by luchangcheng
    //rtc_init();
    //printf("[rtc_init] done!");
#endif
    disk_init();
    binit();    // buffer cache
    fileinit(); // file table

    //test_proc_init();
    userinit(); // first user process
    printf("hart 0 init done\n");

    for (int i = 1; i < NCPU; i++)
    {
      unsigned long mask = 1 << i;
      sbi_send_ipi(&mask);
    }
    __sync_synchronize();
    started = 1;
  }
  else
  {
    // hart 1
    while (started == 0)
      ;
    __sync_synchronize();
#ifdef DEBUG
    printf("hart %d enter main()...\n", hartid);
#endif
    kvminithart();
    trapinithart();
    timerinit();    // set up timer interrupt handler
    plicinithart(); // ask PLIC for device interrupts
    printf("hart 1 init done\n");
  }

  scheduler();
}
