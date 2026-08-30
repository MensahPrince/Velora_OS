# ============================================================
# echo.s
# The disk-resident test program for Velora OS's filesystem demo: a real,
# freestanding x86-64 ELF64 executable, assembled and linked by the host
# toolchain (as/ld — see build.rs) rather than hand-encoded the way
# src/userspace.rs's shellcode demos are. It's linked, packed onto a
# FAT16 disk image, and read back through src/fs.rs and src/elf.rs at
# boot, exactly the way a real userspace binary would be.
#
# Behavior: print a one-line banner once (proving the from-disk binary
# actually ran), then loop forever reading one byte from stdin (the
# keyboard, via Velora's sys_read) and writing it straight back to stdout
# — the same read/write echo loop every ring-3 demo in this kernel runs,
# just arrived at via a real on-disk ELF instead of an embedded one.
#
# Calling convention (see src/syscall.rs): RAX = syscall number in, RDI/
# RSI/RDX = up to three arguments, `int 0x80`, RAX = return value.
#   SYS_WRITE = 0  write(fd, buf, len)
#   SYS_READ  = 1  read(fd, buf, len)
# ============================================================

.section .text
.global _start
_start:
    mov $0, %rax            # SYS_WRITE
    mov $1, %rdi             # fd = stdout
    lea banner(%rip), %rsi
    mov $banner_len, %rdx
    int $0x80

read_loop:
    mov $1, %rax             # SYS_READ
    xor %rdi, %rdi             # fd = stdin
    lea buf(%rip), %rsi
    mov $1, %rdx
    int $0x80
    test %rax, %rax
    jz read_loop              # sys_read never blocks — poll until we get one

    mov $0, %rax              # SYS_WRITE
    mov $1, %rdi                # fd = stdout
    lea buf(%rip), %rsi
    mov $1, %rdx
    int $0x80
    jmp read_loop

.section .rodata
banner:
    .ascii "ECHO.ELF: loaded from the FAT16 disk and running\n"
banner_len = . - banner

.section .bss
buf:
    .byte 0
