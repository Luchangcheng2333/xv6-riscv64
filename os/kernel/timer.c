// Timer Interrupt handler

#include "types.h"
#include "param.h"
#include "riscv.h"
#include "defs.h"
#include "sbi.h"
#include "memlayout.h"
#include "uarths.h"
#include "proc.h"

uint ticks;

void timerinit()
{
    // enable supervisor-mode timer interrupts.
    w_sie(r_sie() | SIE_STIE);
    set_next_timeout();
#ifdef DEBUG
    printf("timerinit\n");
#endif
}

void set_next_timeout()
{
    // There is a very strange bug,
    // if comment the `printf` line below
    // the timer will not work.

    // this bug seems to disappear automatically
    // printf("");
    sbi_set_timer(r_time() + INTERVAL);
}

void timer_tick(int is_kernel_trap)
{
    acquire(&tickslock);
    ticks++;
    wakeup(&ticks);
    release(&tickslock);
    set_next_timeout();
}
