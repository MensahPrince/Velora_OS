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
# Also this kernel's proof that SYS_SPAWN's argument bytes actually reach
# a spawned program: at entry, RDI/RSI hold the argument block's address
# and length (see src/userspace.rs's enter_ring3 doc comment — a separate
# convention from the RDI/RSI/RDX/RCX one below, which only applies once
# _start starts issuing its own `int 0x80`s). If disk/shell.s was given
# anything after "GREET.ELF " on the command line, it ends up here and
# gets printed back verbatim, proving the whole path — shell parses the
# line, SYS_SPAWN carries it, elf::load maps it into this program's own
# address space — actually worked.
#
# Calling convention (see src/syscall.rs): RAX = syscall number in, RDI/
# RSI/RDX/RCX = up to four arguments, `int 0x80`, RAX = return value.
#   SYS_WRITE = 0  write(fd, buf, len)
#   SYS_EXIT  = 2  exit()
# ============================================================

.section .text
.global _start
_start:
    mov %rdi, %rbx              # args_ptr, saved across the syscalls below
    mov %rsi, %r12                # args_len

    mov $0, %rax                # SYS_WRITE
    mov $1, %rdi                 # fd = stdout
    lea banner(%rip), %rsi
    mov $banner_len, %rdx
    int $0x80

    test %r12, %r12
    jz no_args

    mov $0, %rax                # SYS_WRITE — "got args: " prefix
    mov $1, %rdi
    lea args_prefix(%rip), %rsi
    mov $args_prefix_len, %rdx
    int $0x80

    mov $0, %rax                # SYS_WRITE — the argument bytes, verbatim
    mov $1, %rdi
    mov %rbx, %rsi
    mov %r12, %rdx
    int $0x80

    mov $0, %rax                # SYS_WRITE — trailing newline
    mov $1, %rdi
    lea newline(%rip), %rsi
    mov $1, %rdx
    int $0x80

no_args:
    mov $2, %rax                # SYS_EXIT
    int $0x80

.section .rodata
banner:
    .ascii "GREET.ELF: spawned via sys_spawn, running, exiting now\n"
banner_len = . - banner
args_prefix:
    .ascii "GREET.ELF: got args: "
args_prefix_len = . - args_prefix
newline:
    .ascii "\n"
