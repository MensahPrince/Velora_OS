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
# Everything in the line after the first space, if any, is passed through
# to the new program as its argument bytes (SYS_SPAWN's args_ptr/args_len —
# see src/syscall.rs) rather than being treated as part of the path. This
# shell doesn't tokenize those bytes into individual arguments itself —
# the new program gets them raw and decides what they mean, the same way
# `disk/greet.s` just prints them back verbatim to prove the plumbing
# works.
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
# Up/Down recall previous lines from a small in-memory history (see
# `history_lines`/`history_lens` below), most-recent-first, the same way
# a real shell's line editor does. Unlike a plain typed character,
# `task::keyboard::print_keypresses` deliberately does *not* echo these —
# they arrive as a multi-byte ANSI/VT220 escape sequence
# (`task::keyboard::ansi_escape_sequence`), not a character, so there is
# nothing sensible for it to print — so recalling a history entry has to
# erase and redraw the line on screen explicitly here (`history_load_into_line`),
# the one place in this file that *does* write characters it didn't read
# back out.
#
# Known limitations:
#   - Only Up/Down are handled. Left/Right (cursor movement within the
#     line) and Home/End/PageUp/PageDown/the function keys are recognized
#     just well enough to be drained without leaking stray bytes into the
#     line buffer, then otherwise ignored — real in-line editing is future
#     work.
#   - Pressing Down past the newest recalled entry always clears the line;
#     it doesn't restore whatever you'd been typing before you started
#     browsing, the way a real shell's line editor would.
#   - A lone Escape keypress (not the start of a real sequence) is
#     silently swallowed: there's no timer syscall here to distinguish
#     "Escape, pressed alone" from "Escape, first byte of a sequence
#     whose rest just hasn't arrived yet" the way a real terminal does
#     with a short timeout, so this shell always assumes more bytes are
#     coming and blocks reading them.
#   - Same as a real shell without job control: if the program you run
#     doesn't exit (ECHO.ELF, for instance, loops forever), SYS_WAIT never
#     returns and the prompt doesn't come back — there's no Ctrl+C/SIGINT
#     here to reach for.
#
# Calling convention (see src/syscall.rs): RAX = syscall number in, RDI/
# RSI/RDX/RCX = up to four arguments, `int 0x80`, RAX = return value.
# Every register besides RAX is preserved across a syscall, so `%rbx`
# (line buffer address), `%r12` (current line length), and `%r13`
# (history browse offset) stay live across every `int 0x80` in this file
# without needing to be reloaded. `read_byte` and the history helpers
# below are real `call`/`ret` subroutines — safe here (unlike the raw
# shellcode demos in src/userspace.rs, which deliberately never push
# anything) because a program loaded through the real ELF loader
# (src/elf.rs) gets its own dedicated stack page, separate from its
# code/data.
#   SYS_WRITE = 0  write(fd, buf, len)
#   SYS_READ  = 1  read(fd, buf, len)
#   SYS_SPAWN = 5  spawn(path, path_len, args_ptr, args_len) -> pid
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
    xor %r13, %r13                # r13 = history browse offset (0 = live line)

read_char:
    call read_byte                 # blocks until a byte is available; result in %al

    cmp $0x1B, %al                  # ESC — start of an ANSI escape sequence?
    je handle_escape
    cmp $0x08, %al                   # backspace?
    je handle_backspace
    cmp $0x0A, %al                    # newline (LF)?
    je handle_newline
    cmp $0x0D, %al                     # newline (CR, some layouts use this for Enter)?
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

    call history_push                 # remember the whole line before splitting it

    # Split on the first space: everything before it is the path, whatever
    # follows (if anything) is passed through to the new program verbatim
    # as its argument bytes — this shell doesn't parse or tokenize them
    # itself, it just hands off where they start and how long they are.
    xor %rax, %rax
.Lfind_space:
    cmp %r12, %rax
    jge .Lfind_space_done            # reached the end — no space in this line
    cmpb $0x20, (%rbx, %rax)
    je .Lfind_space_done
    inc %rax
    jmp .Lfind_space
.Lfind_space_done:

    mov %rax, %r14                    # r14 = path_len
    cmp %r12, %r14
    jge .Lno_args                      # no space found: whole line is the path, no args
    lea 1(%rbx, %r14), %r15             # args_ptr = line_buf + path_len + 1 (skip the space)
    mov %r12, %r8
    sub %r14, %r8
    dec %r8                              # args_len = r12 - path_len - 1
    jmp .Lspawn
.Lno_args:
    xor %r15, %r15
    xor %r8, %r8
.Lspawn:
    mov $5, %rax                      # SYS_SPAWN
    mov %rbx, %rdi                     # path_ptr = line_buf
    mov %r14, %rsi                      # path_len
    mov %r15, %rdx                       # args_ptr
    mov %r8, %rcx                         # args_len
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

# Reads exactly one byte from stdin, blocking (via sys_read's own polling
# contract — see the call site) until one is available. Result in %al.
# Clobbers %rax/%rdi/%rsi/%rdx, same as any syscall.
read_byte:
    mov $1, %rax                  # SYS_READ
    xor %rdi, %rdi                 # fd = stdin
    lea char_buf(%rip), %rsi
    mov $1, %rdx
    int $0x80
    test %rax, %rax
    jz read_byte                    # sys_read never blocks — poll until we get one
    movb char_buf(%rip), %al
    ret

handle_escape:
    call read_byte
    cmp $0x5B, %al                  # '[' — anything else isn't a sequence this
    jne read_char                    # shell recognizes; drop it (see file header)

    call read_byte                    # the "which key" byte (arrows), or the
                                        # first digit of a longer ESC[n~ code
    cmp $0x41, %al                      # 'A' = Up
    je history_older
    cmp $0x42, %al                       # 'B' = Down
    je history_newer
    cmp $0x43, %al                        # 'C' = Right, 'D' = Left — not
    je read_char                           # handled yet, and (unlike the
    cmp $0x44, %al                          # codes below) nothing left to drain
    je read_char

drain_csi:
    # Home/Insert/PageUp/PageDown/the function keys all end in a run of
    # digits then '~' (e.g. ESC[5~, ESC[11~). Not handled yet either, but
    # every byte through the '~' still has to be consumed here so it
    # doesn't leak into the line buffer as stray characters.
    cmp $0x7E, %al                  # '~'
    je read_char
    call read_byte
    jmp drain_csi

# Up: browse one entry further back in history (does nothing at the
# oldest stored entry, or if there's no history yet).
history_older:
    mov history_count(%rip), %rax
    test %rax, %rax
    jz read_char
    cmp %rax, %r13                   # already at the oldest entry?
    jge read_char
    inc %r13
    call history_load_into_line
    jmp read_char

# Down: browse one entry back toward the live line (clearing it once
# there, rather than restoring whatever was being typed — see the known
# limitations above). Does nothing if not currently browsing.
history_newer:
    test %r13, %r13
    jz read_char
    dec %r13
    jz history_clear_line
    call history_load_into_line
    jmp read_char

history_clear_line:
    mov %r12, %r8                     # erase whatever's currently on screen
    test %r8, %r8
    jz read_char
    mov $0, %rax                       # SYS_WRITE
    mov $1, %rdi
    lea backspace_run(%rip), %rsi
    mov %r8, %rdx
    int $0x80
    xor %r12, %r12
    jmp read_char

# Copies history entry "%r13 entries back from newest" (1 = most recent)
# into line_buf, updates %r12 to its length, and redraws the line on
# screen — erasing the %r12 characters that were there beforehand, then
# writing the recalled ones. Clobbers %rax/%rcx/%rdx/%r8/%r9.
history_load_into_line:
    mov %r12, %r8                       # old on-screen length, to erase first

    mov history_next(%rip), %rax
    sub %r13, %rax
    and $(HISTORY_CAPACITY - 1), %rax    # slot index, wrapped (capacity is a power of two)

    lea history_lens(%rip), %rdx
    movzbq (%rdx, %rax), %rcx              # %rcx = this entry's length

    mov %rax, %rdx
    imul $LINE_BUF_SIZE, %rdx, %rdx
    lea history_lines(%rip), %r9
    add %rdx, %r9                            # %r9 = pointer to this entry's bytes

    xor %rdx, %rdx
.Lload_copy:
    cmp %rcx, %rdx
    jge .Lload_copy_done
    movb (%r9, %rdx), %al
    movb %al, (%rbx, %rdx)
    inc %rdx
    jmp .Lload_copy
.Lload_copy_done:

    test %r8, %r8                          # erase the old line, if any
    jz .Lload_skip_erase
    mov $0, %rax                            # SYS_WRITE
    mov $1, %rdi
    lea backspace_run(%rip), %rsi
    mov %r8, %rdx
    int $0x80                                # %rcx/%r9 survive — int 0x80 only clobbers RAX (see file header)
.Lload_skip_erase:

    test %rcx, %rcx                        # write the recalled line
    jz .Lload_skip_write
    mov $0, %rax                            # SYS_WRITE
    mov $1, %rdi
    mov %rbx, %rsi
    mov %rcx, %rdx
    int $0x80
.Lload_skip_write:

    mov %rcx, %r12
    ret

# Stores line_buf[0 .. %r12) as the newest history entry, overwriting the
# oldest one once history_lines fills up. Clobbers %rax/%rcx/%rdx/%r9.
history_push:
    mov history_next(%rip), %rax
    mov %rax, %rdx
    imul $LINE_BUF_SIZE, %rdx, %rdx
    lea history_lines(%rip), %r9
    add %rdx, %r9                    # %r9 = destination for this entry's bytes

    xor %rcx, %rcx
.Lpush_copy:
    cmp %r12, %rcx
    jge .Lpush_copy_done
    movb (%rbx, %rcx), %dl
    movb %dl, (%r9, %rcx)
    inc %rcx
    jmp .Lpush_copy
.Lpush_copy_done:

    lea history_lens(%rip), %rdx
    movb %r12b, (%rdx, %rax)          # line_buf is capped at LINE_BUF_SIZE (64), fits a byte

    inc %rax
    and $(HISTORY_CAPACITY - 1), %rax
    mov %rax, history_next(%rip)

    mov history_count(%rip), %rax
    cmp $HISTORY_CAPACITY, %rax
    jge .Lpush_done                   # already saturated — oldest entry was just overwritten
    inc %rax
    mov %rax, history_count(%rip)
.Lpush_done:
    ret

.section .rodata
banner:
    .ascii "Velora shell. Try: ECHO.ELF  GREET.ELF  (Up/Down for history)\n"
banner_len = . - banner
prompt_str:
    .ascii "\n> "
prompt_len = . - prompt_str
fail_str:
    .ascii "spawn failed\n"
fail_len = . - fail_str
# One backspace (0x08) per byte, enough to erase a full line_buf's worth.
# src/vga_buffer.rs's write_byte(0x08) both steps the cursor back and
# blanks the cell in one go, so writing N of these erases the last N
# characters with no separate "blank it" pass needed.
backspace_run:
    .fill LINE_BUF_SIZE, 1, 0x08

.section .bss
char_buf:
    .byte 0
LINE_BUF_SIZE = 64
line_buf:
    .skip LINE_BUF_SIZE

# A small ring buffer of previously submitted lines — see history_push/
# history_load_into_line above. Capacity is a power of two so wrapping
# the write index is a plain AND mask rather than a division.
HISTORY_CAPACITY = 8
history_lines:
    .skip HISTORY_CAPACITY * LINE_BUF_SIZE
history_lens:
    .skip HISTORY_CAPACITY
history_count:
    .quad 0                # entries stored so far, saturating at HISTORY_CAPACITY
history_next:
    .quad 0                # ring-buffer slot the *next* pushed entry will use
