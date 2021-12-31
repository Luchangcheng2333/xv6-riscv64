
#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"
#include "binformat.h"
#include "fat32.h"
#include "debug.h"

const char *env[] = {"SHELL=shell",
                     "PWD=/",
                     "HOME=/",
                     "USER=root",
                     "MOTD_SHOWN=pam",
                     "LANG=C.UTF-8",
                     "INVOCATION_ID=e9500a871cf044d9886a157f53826684",
                     "TERM=vt220",
                     "SHLVL=2",
                     "JOURNAL_STREAM=8:9265",
                     "PATH=/",
                     "OLDPWD=/root",
                     "_=busybox",
                     0};

const int kElfInfoNum = 30;
int CopyString2Stack(char *strs[], struct BinProgram * bin_prog)
{
  int i = 0;
  for (; strs[i]; i++) {
    if (i > MAXARG)
      return -1;
    bin_prog->sp -= strlen(strs[i]) + 1;
    bin_prog->sp -= bin_prog->sp % 16;
    if (bin_prog->sp < bin_prog->stackbase) {
      return -1;
    }
    if (copyout(bin_prog->pagetable, bin_prog->sp, strs[i], strlen(strs[i]) + 1) < 0)
      return -1;
    (bin_prog->ustack)[i] = bin_prog->sp;
  }
  (bin_prog->ustack)[i] = 0;
  int c = i - bin_prog->stack_top;
  bin_prog->stack_top = i + 1;
  return c;
}

uint64 CopyString(const char *s, struct BinProgram * bin_prog)
{
  bin_prog->sp -= strlen(s) + 1;
  bin_prog->sp -= bin_prog->sp % 16;
  if (copyout(bin_prog->pagetable, bin_prog->sp, (char *)s, strlen(s) + 1) < 0)
    return -1;
  return bin_prog->sp;
}


uint64 CreateUserStack(struct BinProgram *bin_program, struct elfhdr *elf)
{
  int index = bin_program->argc + bin_program->envc + 2;

  uint64 filename = CopyString("/busybox", bin_program);
#define NEW_AUX_ENT(id, val)                                                   \
  do {                                                                         \
    bin_program->ustack[index++] = id;                                         \
    bin_program->ustack[index++] = val;                                        \
  } while (0)

  NEW_AUX_ENT(0x28, 0);
  NEW_AUX_ENT(0x29, 0);
  NEW_AUX_ENT(0x2a, 0);
  NEW_AUX_ENT(0x2b, 0);
  NEW_AUX_ENT(0x2c, 0);
  NEW_AUX_ENT(0x2d, 0);
  NEW_AUX_ENT(AT_PHDR, elf->phoff + bin_program->vaddr);               // 3
  NEW_AUX_ENT(AT_PHENT, sizeof(struct proghdr));  // 4
  NEW_AUX_ENT(AT_PHNUM, elf->phnum);              // 5
  NEW_AUX_ENT(AT_PAGESZ, PGSIZE);                 // 6
  NEW_AUX_ENT(AT_BASE, 0);                        // 7
  NEW_AUX_ENT(AT_FLAGS, 0);                       // 8
  NEW_AUX_ENT(AT_ENTRY, elf->entry);              // 9
  NEW_AUX_ENT(AT_UID, 0);                         // 11
  NEW_AUX_ENT(AT_EUID, 0);                        // 12
  NEW_AUX_ENT(AT_GID, 0);                         // 13
  NEW_AUX_ENT(AT_EGID, 0);                        // 14
  NEW_AUX_ENT(AT_HWCAP, 0x112d);                  // 16
  NEW_AUX_ENT(AT_CLKTCK, 64);                     // 17
  NEW_AUX_ENT(AT_EXECFN, filename);               // 31
  NEW_AUX_ENT(0, 0);
#undef NEW_AUX_ENT
  bin_program->sp -= sizeof(uint64) * index;
  
  #ifdef DEBUG
  printf("[exec] auxv[] stack pointer = 0x%x\n", bin_program->sp + (bin_program->argc + bin_program->envc + 2) * sizeof(uint64));
  printf("[exec] envp[] stack pointer = 0x%x\n", bin_program->sp + (bin_program->argc + 1) * sizeof(uint64));
  printf("[exec] argv[] stack pointer = 0x%x\n", bin_program->sp);
  #endif
  if (copyout(bin_program->pagetable, bin_program->sp,
              (char *)bin_program->ustack, sizeof(uint64) * index)) {
    return -1;
  }
  uint64 argc = bin_program->argc;
  bin_program->sp -= sizeof(uint64);
  
  #ifdef DEBUG
  printf("[exec] argc stack pointer = 0x%x\n", bin_program->sp);
  #endif
  
  if (copyout(bin_program->pagetable, bin_program->sp, (char *)&argc, sizeof(uint64)) < 0)
    return -1;
  return 0;
}

// Load a program segment into pagetable at virtual address va.
// va must be page-aligned
// and the pages from va to va+sz must already be mapped.
// Returns 0 on success, -1 on failure.
static int
loadseg(pagetable_t pagetable, uint64 va, struct dirent *ep, uint offset, uint sz)
{
  uint i, n;
  uint64 pa;
  uint64 off = va & (PGSIZE - 1);
  uint64 k = PGSIZE;

  for(i = 0; i < sz; i += k){
    pa = walkaddr(pagetable, va + i);
    if(pa == 0)
      panic("loadseg: address should exist");
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
      
    // adjust for not aligned segments
    if (off != 0)
    {
      int need_to_read = PGSIZE - off; // read to the end of the last segment
      if (sz - i < need_to_read)
      {
        need_to_read = sz - i;
      }
      if(eread(ep, 0, (uint64)pa + off, offset + i, need_to_read) != need_to_read)
        return -1;
      k = need_to_read;
      off = 0;
      continue;
    }
    else
    {
      k = PGSIZE;
    }
    if(eread(ep, 0, (uint64)pa, offset+i, n) != n)
      return -1;
  }

  return 0;
}

int exec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 sz = 0, sp, ustack[MAXARG+1], stackbase, oldsz;
  struct BinProgram bin_prog;
  struct elfhdr elf;
  struct dirent *ep;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();
  if((ep = ename(path)) == 0) {
    return -1;
  }
  elock(ep);

  // Check ELF header
  if(eread(ep, 0, (uint64) &elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // Load program into memory.
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(eread(ep, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph)){
      goto bad;
    }
    if(ph.type != ELF_PROG_LOAD) // only load type segment need map 
      continue;
    if(ph.memsz < ph.filesz) // memsz must > filesz, we will alloc memsz & map filesz
    {
      __debug_error("exec", "no enough memory!\n");
      goto bad;
    }
    if(ph.vaddr + ph.memsz < ph.vaddr)
    {
      __debug_error("exec", "unexpected load error!\n");
      goto bad;
    }
    uint64 sz1;
    if((sz1 = uvmalloc(pagetable, sz, ph.vaddr + ph.memsz)) == 0)
    {
      __debug_error("exec", "alloc memory error!\n");
      goto bad;
    }
    sz = sz1;
    if(loadseg(pagetable, ph.vaddr, ep, ph.off, ph.filesz) < 0)
    {
      __debug_error("exec", "load segment error!\n");
      goto bad;
    }
  }

  eunlock(ep);
  eput(ep);
  ep = 0;

  p = myproc();
  oldsz = p->heap_addr;

  // Allocate 4 pages at the next page boundary. Use 2,3,4 as the user stack.
  sz = PGROUNDUP(sz);
  uint64 sz1;
  if((sz1 = uvmalloc(pagetable, sz, sz + 4*PGSIZE)) == 0)
    goto bad;
  sz = sz1;
  
  // Make the first page invaild
  uvmclear(pagetable, sz-3*PGSIZE); 
  sp = sz;
  stackbase = sp - PGSIZE;
  sp -= sizeof(uint64);

  // Fork from startOS by huiyu
  bin_prog.stack_top = 0;
  bin_prog.sp = sp;
  bin_prog.stackbase = stackbase;
  bin_prog.pagetable = pagetable;
  bin_prog.ustack = ustack;
  bin_prog.vaddr = ph.vaddr;
  
  // push environment strings
  bin_prog.envc = CopyString2Stack((char **)env, &bin_prog);

  #ifdef DEBUG
  printf("[exec] envc = %d\n", bin_prog.envc);
  printf("[exec] env string stack pointer = 0x%x\n", bin_prog.sp);
  #endif

  // push argument strings
  bin_prog.argc = CopyString2Stack((char **)argv, &bin_prog);

  #ifdef DEBUG
  printf("[exec] argc = %d\n", bin_prog.argc);
  printf("[exec] arg string stack pointer = 0x%x\n", bin_prog.sp);
  #endif

  

  // push argc, argv[], envp[], auxv[]
  CreateUserStack(&bin_prog, &elf);

  sp = bin_prog.sp;

  // arguments to user main(argc, argv)
  p->trapframe->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
  
  // Commit to the user image.
  p->trapframe->ra = 0;
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->heap_addr = sz;
  p->trapframe->epc = elf.entry;  // initial program counter = main

  #ifdef DEBUG
  printf("[exec] entry is: 0x%x\n", elf.entry);
  #endif

  p->trapframe->sp = sp;          // initial stack pointer
  proc_freepagetable(oldpagetable, oldsz);
  sfence_vma();
  fence_i();
  return 0; // this ends up in a0

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(ep){
    eunlock(ep);
    eput(ep);
  }
  return -1;
}
