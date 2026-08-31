# ============================================================
# greet.s
# A second disk-resident test program, for src/syscall.rs's SYS_SPAWN/
# SYS_WAIT demo (see src/userspace.rs's spawn_wait_demo). echo.s (the
# other one) loops forever and never exits — fine for a demo that only
# ever proves ring 3 can read/write, but useless as something to `wait()`
# for, since that wait would never come back. This one prints a banner
# and exits immediately, so a parent that spawns it and waits gets its
# wait back in finite time.
#
# Calling convention (see src/syscall.rs): RAX = syscall number in, RDI/
# RSI/RDX = up to three arguments, `int 0x80`, RAX = return value.
#   SYS_WRITE = 0  write(fd, buf, len)
#   SYS_EXIT  = 2  exit()
# ============================================================

.section .text
.global _start
_start:
    mov $0, %rax             # SYS_WRITE
    mov $1, %rdi              # fd = stdout
    lea banner(%rip), %rsi
    mov $banner_len, %rdx
    int $0x80

    mov $2, %rax              # SYS_EXIT
    int $0x80

.section .rodata
banner:
    .ascii "GREET.ELF: spawned via sys_spawn, running, exiting now\n"
banner_len = . - banner
