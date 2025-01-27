
#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "defs.h"
#include "sbi.h"
#include "plic.h"

//
// the riscv Platform Level Interrupt Controller (PLIC).
//

/*void*/
/*plicinit(void)*/
/*{*/
  /*// set desired IRQ priorities non-zero (otherwise disabled).*/
  /*#ifndef QEMU*/
  /*writel(1, PLIC + IRQN_UARTHS_INTERRUPT * sizeof(uint32));*/
  /*writel(1, PLIC + IRQN_DMA0_INTERRUPT * sizeof(uint32));*/
  /*#else*/
  /**(uint32*)(PLIC + UART_IRQ*4) = 1;*/
  /**(uint32*)(PLIC + DISK_IRQ*4) = 1;*/
  /*#endif*/
  /*#ifdef DEBUG*/
  /*printf("plicinit\n");*/
  /*#endif*/
/*}*/

void plicinit(void) {
	writed(1, PLIC + DISK_IRQ * sizeof(uint32));
	writed(1, PLIC + UART_IRQ * sizeof(uint32));

	#ifdef DEBUG 
	printf("plicinit\n");
	#endif 
}

void
plicinithart(void)
{
  int hart = cpuid();
  #ifdef QEMU
  // set uart's enable bit for this hart's S-mode. 
  *(uint32*)PLIC_SENABLE(hart)= (1 << UART_IRQ) | (1 << DISK_IRQ);
  // set this hart's S-mode priority threshold to 0.
  *(uint32*)PLIC_SPRIORITY(hart) = 0;
  #else
  uint32 *hart_m_enable = (uint32*)PLIC_MENABLE(hart);
  *(hart_m_enable) = readd(hart_m_enable) | (1 << DISK_IRQ);
  uint32 *hart0_m_int_enable_hi = hart_m_enable + 1;
  *(hart0_m_int_enable_hi) = readd(hart0_m_int_enable_hi) | (1 << (UART_IRQ % 32));
  #endif
  #ifdef DEBUG
  printf("plicinithart\n");
  #endif
}

// ask the PLIC what interrupt we should serve.
int
plic_claim(void)
{
  int hart = cpuid();
  int irq;
  #ifndef QEMU
  irq = *(uint32*)PLIC_MCLAIM(hart);
  #else
  irq = *(uint32*)PLIC_SCLAIM(hart);
  #endif
  return irq;
}

// tell the PLIC we've served this IRQ.
void
plic_complete(int irq)
{
  int hart = cpuid();
  #ifndef QEMU
  *(uint32*)PLIC_MCLAIM(hart) = irq;
  #else
  *(uint32*)PLIC_SCLAIM(hart) = irq;
  #endif
}

