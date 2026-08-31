# ============================================================
# shell.s
# Velora OS's first real interactive program: prints a prompt, reads a
# line of typed input, and spawns whatever program name that line names
# (syscall::SYS_SPAWN), waiting for it to finish (SYS_WAIT) before
# prompting again — the piece every earlier demo in this kernel was
# building toward, but none of them actually were: this is the first
# thing here that turns typed input into a *launched program* rather than
# just echoing it back or running one fixed, hardcoded command.
#
# No explicit echo of typed characters: `task::keyboard::print_keypresses`
# (running forever in the kernel's own background executor) already prints
# every decoded key to the screen — including erasing on backspace — as a
# side effect of feeding the same queue SYS_READ pulls from. Echoing here
# too would just double every character on screen, the same reason the
# read/write echo demos elsewhere in this kernel stay disabled by default.
# This program only needs to track the line *itself* (for spawning once
# Enter is pressed), not display it.
#
# Known limitation, same as a real shell without job control: if the
# program you run doesn't exit (ECHO.ELF, for instance, loops forever),
# SYS_WAIT never returns and the prompt doesn't come back — there's no
# Ctrl+C/SIGINT here to reach for.
#
# Calling convention (see src/syscall.rs): RAX = syscall number in, RDI/
# RSI/RDX = up to three arguments, `int 0x80`, RAX = return value. Every
# register besides RAX is preserved across a syscall, so `%r12` (current
# line length) and `%rbx` (line buffer address) stay live across every
# `int 0x80` in this file without needing to be reloaded.
#   SYS_WRITE = 0  write(fd, buf, len)
#   SYS_READ  = 1  read(fd, buf, len)
#   SYS_SPAWN = 5  spawn(path, path_len) -> pid
#   SYS_WAIT  = 6  wait(pid)
# ============================================================

.section .text
.global _start
_start:
    mov $0, %rax                # SYS_WRITE
    mov $1, %rdi
    lea banner(%rip), %rsi
    mov $banner_len, %rdx
    int $0x80

    lea line_buf(%rip), %rbx

prompt:
    mov $0, %rax                # SYS_WRITE
    mov $1, %rdi
    lea prompt_str(%rip), %rsi
    mov $prompt_len, %rdx
    int $0x80

    xor %r12, %r12               # r12 = current line length

read_char:
    mov $1, %rax                  # SYS_READ
    xor %rdi, %rdi                 # fd = stdin
    lea char_buf(%rip), %rsi
    mov $1, %rdx
    int $0x80
    test %rax, %rax
    jz read_char                   # sys_read never blocks — poll until we get one

    movb char_buf(%rip), %al

    cmp $0x08, %al                  # backspace?
    je handle_backspace
    cmp $0x0A, %al                   # newline (LF)?
    je handle_newline
    cmp $0x0D, %al                    # newline (CR, some layouts use this for Enter)?
    je handle_newline

    cmp $LINE_BUF_SIZE, %r12            # line buffer full?
    jge read_char                        # ignore extra characters rather than overflow it

    movb %al, (%rbx, %r12)
    inc %r12
    jmp read_char

handle_backspace:
    test %r12, %r12
    jz read_char                    # nothing typed yet — ignore
    dec %r12
    jmp read_char

handle_newline:
    test %r12, %r12
    jz prompt                        # empty line — just show the prompt again

    mov $5, %rax                      # SYS_SPAWN
    mov %rbx, %rdi                     # path = line_buf
    mov %r12, %rsi                      # path_len
    int $0x80

    cmp $-1, %rax
    je spawn_failed

    mov %rax, %rdi                       # pid -> rdi for wait
    mov $6, %rax                          # SYS_WAIT
    int $0x80
    jmp prompt

spawn_failed:
    mov $0, %rax                           # SYS_WRITE
    mov $1, %rdi
    lea fail_str(%rip), %rsi
    mov $fail_len, %rdx
    int $0x80
    jmp prompt

.section .rodata
banner:
    .ascii "Velora shell. Try: ECHO.ELF  GREET.ELF\n"
banner_len = . - banner
prompt_str:
    .ascii "\n> "
prompt_len = . - prompt_str
fail_str:
    .ascii "spawn failed\n"
fail_len = . - fail_str

.section .bss
char_buf:
    .byte 0
LINE_BUF_SIZE = 64
line_buf:
    .skip LINE_BUF_SIZE
