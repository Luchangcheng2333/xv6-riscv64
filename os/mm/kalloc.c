// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.


#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"

int free_physical_pages;

void freerange(void *pa_start, void *pa_end);

extern char kernel_end[]; // first address after kernel.

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  struct run *freelist;
} kmem;

void
kinit()
{
  initlock(&kmem.lock, "kmem");
  // printf("kernel_end: %p, phystop: %p\n", kernel_end, (void*)PHYSTOP);
  free_physical_pages = 0;
  freerange(kernel_end, (void*)PHYSTOP);
  printf("kinit done! free mem size: %d KB\n", free_physical_pages * 4);
  #ifdef DEBUG
  printf("kinit\n");
  #endif
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE)
    kfree(p);
}

// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;
  
  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < kernel_end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  acquire(&kmem.lock);
  r->next = kmem.freelist;
  kmem.freelist = r;
  free_physical_pages++;
  release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;
  if(r)
  {
    kmem.freelist = r->next;
    free_physical_pages--;
  }
  release(&kmem.lock);

  if(r)
    memset((char*)r, 0, PGSIZE); // fill with junk
  return (void*)r;
}

uint64
freemem_amount(void)
{
  struct run *r;
  uint64 amount = 0;

  // acquire(&kmem.lock);
  r = kmem.freelist;
  while (r) {
    amount++;
    r = r->next;
  }
  // release(&kmem.lock);

  return amount * PGSIZE;
}
