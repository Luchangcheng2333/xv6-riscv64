platform	:= k210
#platform	:= qemu
# mode := debug
mode := release
readsyscall := n
K=os
U=xv6-user
T=target

OBJS =
ifeq ($(platform), k210)
OBJS += $K/boot/entry_k210.o
else
OBJS += $K/boot/entry_qemu.o
endif

OBJS += \
  $K/kernel/printf.o \
  $K/mm/kalloc.o \
  $K/drivers/intr.o \
  $K/kernel/spinlock.o \
  $K/mm/string.o \
  $K/boot/main.o \
  $K/mm/vm.o \
  $K/kernel/proc.o \
  $K/kernel/swtch.o \
  $K/trap/trampoline.o \
  $K/trap/trap.o \
  $K/kernel/syscall.o \
  $K/kernel/sysproc.o \
  $K/drivers/bio.o \
  $K/kernel/sleeplock.o \
  $K/fs/file.o \
  $K/fs/pipe.o \
  $K/fs/exec.o \
  $K/fs/sysfile.o \
  $K/trap/kernelvec.o \
  $K/kernel/timer.o \
  $K/kernel/logo.o \
  $K/drivers/disk.o \
  $K/fs/fat32.o \
  $K/drivers/plic.o \
  $K/drivers/console.o \
  $K/kernel/lcc_syscall.o \
  $K/kernel/lcc_variables.o \
  
ifeq ($(platform), k210)
OBJS += \
  $K/drivers/spi.o \
  $K/drivers/gpiohs.o \
  $K/drivers/fpioa.o \
  $K/drivers/utils.o \
  $K/drivers/sdcard.o \
  $K/drivers/dmac.o \
  $K/drivers/sysctl.o \
  $K/drivers/rtc.o \

else
OBJS += \
  $K/drivers/virtio_disk.o \
  #$K/uart.o \

endif

QEMU = qemu-system-riscv64

ifeq ($(platform), k210)
RUSTSBI = ./bootloader/SBI/sbi-k210
else
RUSTSBI = ./bootloader/SBI/sbi-qemu
endif



TOOLPREFIX	:= riscv64-unknown-elf-
# TOOLPREFIX	:= riscv64-linux-gnu-
CC = $(TOOLPREFIX)gcc
AS = $(TOOLPREFIX)gas
LD = $(TOOLPREFIX)ld
OBJCOPY = $(TOOLPREFIX)objcopy
OBJDUMP = $(TOOLPREFIX)objdump

CFLAGS = -Wall -Werror -O -fno-omit-frame-pointer -ggdb -g
CFLAGS += -MD
CFLAGS += -mcmodel=medany
CFLAGS += -ffreestanding -fno-common -nostdlib -mno-relax
CFLAGS += -I./os/include -I.
CFLAGS += $(shell $(CC) -fno-stack-protector -E -x c /dev/null >/dev/null 2>&1 && echo -fno-stack-protector)

ifeq ($(mode), debug) 
CFLAGS += -DDEBUG 
endif 

ifeq ($(platform), qemu)
CFLAGS += -DQEMU
endif

ifeq ($(readsyscall), y)
CFLAGS += -DREADSYSCALL
endif

LDFLAGS = -z max-page-size=4096

ifeq ($(platform), k210)
linker = ./linker/k210.ld
endif

ifeq ($(platform), qemu)
linker = ./linker/qemu.ld
endif


all: build
	@$(OBJCOPY) $T/kernel --strip-all -O binary $(image)
	@$(OBJCOPY) $(RUSTSBI) --strip-all -O binary $(k210)
	@dd if=$(image) of=$(k210) bs=128k seek=1
	@$(OBJDUMP) -D -b binary -m riscv $(k210) > $T/k210.asm
	@cp $(k210) .


# Compile Kernel
$T/kernel: $(OBJS) $(linker) $U/initcode
	@if [ ! -d "./target" ]; then mkdir target; fi
	@$(LD) $(LDFLAGS) -T $(linker) -o $T/kernel $(OBJS)
	@$(OBJDUMP) -S $T/kernel > $T/kernel.asm
	@$(OBJDUMP) -t $T/kernel | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $T/kernel.sym
  
build: $T/kernel userprogs

# Compile RustSBI
RUSTSBI:
ifeq ($(platform), k210)
	@cd ./bootloader/SBI/rustsbi-k210 && cargo build && cp ./target/riscv64gc-unknown-none-elf/debug/rustsbi-k210 ../sbi-k210
	@$(OBJDUMP) -S ./bootloader/SBI/sbi-k210 > $T/rustsbi-k210.asm
else
	@cd ./bootloader/SBI/rustsbi-qemu && cargo build && cp ./target/riscv64gc-unknown-none-elf/debug/rustsbi-qemu ../sbi-qemu
	@$(OBJDUMP) -S ./bootloader/SBI/sbi-qemu > $T/rustsbi-qemu.asm
endif

rustsbi-clean:
	@cd ./bootloader/SBI/rustsbi-k210 && cargo clean
	@cd ./bootloader/SBI/rustsbi-qemu && cargo clean

image = $T/kernel.bin
k210 = $T/k210.bin
k210-serialport := /dev/ttyUSB0

ifndef CPUS
CPUS := 2
endif

ifndef debug
debug := no
endif

QEMUOPTS = -machine virt -kernel $T/kernel -m 1024M -nographic

# use multi-core 
QEMUOPTS += -smp $(CPUS)

QEMUOPTS += -bios $(RUSTSBI)

# import virtual disk image
QEMUOPTS += -drive file=disk.img,if=none,format=raw,id=x0 
QEMUOPTS += -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0



run: build
ifeq ($(platform), k210)
	@$(OBJCOPY) $T/kernel --strip-all -O binary $(image)
	@$(OBJCOPY) $(RUSTSBI) --strip-all -O binary $(k210)
	@dd if=$(image) of=$(k210) bs=128k seek=1
	@$(OBJDUMP) -D -b binary -m riscv $(k210) > $T/k210.asm
	@sudo chmod 777 $(k210-serialport)
	@python3 ./tools/kflash.py -p $(k210-serialport) -b 1500000 -t $(k210)
endif
ifeq ($(platform), qemu)
ifeq ($(debug), y)
	$(QEMU) $(QEMUOPTS) -S -s
else
	$(QEMU) $(QEMUOPTS)
endif
endif


$U/initcode: $U/initcode.S
	$(CC) $(CFLAGS) -march=rv64g -nostdinc -I./os/include -Ikernel -c $U/initcode.S -o $U/initcode.o
	$(LD) $(LDFLAGS) -N -e start -Ttext 0 -o $U/initcode.out $U/initcode.o
	$(OBJCOPY) -S -O binary $U/initcode.out $U/initcode
	$(OBJDUMP) -S $U/initcode.o > $U/initcode.asm

tags: $(OBJS) _init
	@etags *.S *.c

ULIB = $U/ulib.o $U/usys.o $U/printf.o $U/umalloc.o

_%: %.o $(ULIB)
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o $@ $^
	$(OBJDUMP) -S $@ > $*.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $*.sym

$U/usys.S : $U/usys.pl
	@perl $U/usys.pl > $U/usys.S

$U/usys.o : $U/usys.S
	$(CC) $(CFLAGS) -c -o $U/usys.o $U/usys.S -I./os/include

$U/_forktest: $U/forktest.o $(ULIB)
	# forktest has less library code linked in - needs to be small
	# in order to be able to max out the proc table.
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o $U/_forktest $U/forktest.o $U/ulib.o $U/usys.o
	$(OBJDUMP) -S $U/_forktest > $U/forktest.asm

# Prevent deletion of intermediate files, e.g. cat.o, after first build, so
# that disk image changes after first build are persistent until clean.  More
# details:
# http://www.gnu.org/software/make/manual/html_node/Chained-Rules.html
.PRECIOUS: %.o

UPROGS=\
	$U/_init \
	$U/_sh \
	$U/_cat \
	$U/_echo \
	$U/_grep\
	$U/_ls\
	$U/_kill\
	$U/_mkdir\
	$U/_xargs\
	$U/_sleep\
	$U/_find\
	$U/_rm\
	$U/_wc\
	$U/_trace\
    $U/_lcc_test\
	# $U/_forktest\
	# $U/_ln\
	# $U/_test\
	# $U/_stressfs\
	# $U/_usertests\
	# $U/_grind\
	# $U/_zombie\

userprogs: $(UPROGS)

dst=/mnt

# Make fs image
fs: $(UPROGS)
	@if [ ! -f "disk.img" ]; then \
		echo "making fs image..."; \
		dd if=/dev/zero of=disk.img bs=512k count=1024; \
		mkfs.vfat -F 32 disk.img; fi
	@sudo mount disk.img $(dst)
	@if [ ! -d "$(dst)/bin" ]; then sudo mkdir $(dst)/bin; fi
	@sudo cp $U/_init $(dst)/init
	@sudo cp $U/_sh $(dst)/sh
	@for file in $$( ls $U/_* ); do \
		sudo cp $$file $(dst)/bin/$${file#$U/_}; done
	@sudo umount $(dst)

# Write sdcard
sdcard: fs
	@if [ "$(sd)" != "" ]; then \
		echo "flashing into sd card..."; \
		sudo dd if=disk.img of=$(sd); \
	else \
		echo "sd card not detected!"; fi

clean: 
	rm -f *.tex *.dvi *.idx *.aux *.log *.ind *.ilg k210.bin \
	os/drivers/*.o os/boot/*.o os/fs/*.o os/trap/*.o os/kernel/*.o os/mm/*.o \
	os/drivers/*.d os/boot/*.d os/fs/*.d os/trap/*.d os/kernel/*.d os/mm/*.d \
	os/drivers/*.asm os/boot/*.asm os/fs/*.asm os/trap/*.asm os/kernel/*.asm os/mm/*.asm \
	os/drivers/*.sym os/boot/*.sym os/fs/*.sym os/trap/*.sym os/kernel/*.sym os/mm/*.sym \
	$T/* \
	$U/initcode $U/initcode.out \
	$U/*.o $U/*.d $U/*.asm $U/*.sym \
	$(UPROGS) \
	$U/usys.S

.PHONY:gdb
gdb:
	@riscv64-unknown-elf-gdb -ex 'file $T/kernel' -ex 'set arch riscv:rv64' -ex 'target remote localhost:1234' -ex 'set disassemble-next-line on'