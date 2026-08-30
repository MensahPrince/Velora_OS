// ============================================================
// syscall.rs
// A real syscall ABI for ring-3 code: register-based arguments and a
// return value, not just a fixed debug message (the earlier `int 0x80`
// handler in src/interrupts.rs).
//
// Convention (loosely Linux-like, but this kernel's own): RAX holds the
// syscall number going in and the return value coming back out; RDI, RSI,
// RDX hold up to three arguments.
// ============================================================

use crate::scheduler;
use core::arch::naked_asm;
use x86_64::registers::control::Cr3;

pub const SYS_WRITE: u64 = 0;
pub const SYS_READ: u64 = 1;

/// The IDT entry (src/interrupts.rs) points directly at this, via
/// `Entry::set_handler_addr` rather than `set_handler_fn` — it can't be a
/// normal `extern "x86-interrupt" fn`, because that calling convention
/// specifically hides the general-purpose registers from us (the compiler
/// relocates them as part of its own generated prologue before our
/// function body ever runs), and reading the syscall number and arguments
/// out of RAX/RDI/RSI/RDX is the entire point here.
///
/// # Safety
/// Must only ever be installed as an interrupt gate for a vector that's
/// reached via `int` from ring 3 (or ring 0) — the body assumes the CPU
/// has already pushed a standard interrupt frame (and, for a ring-3
/// caller, switched to RSP0) before it starts.
#[unsafe(naked)]
pub unsafe extern "C" fn entry() {
    naked_asm!(
        // Save the *entire* general-purpose register set. Not just the
        // ones the calling convention below actually uses: whatever
        // called us gets every register back exactly as it left them
        // (except RAX, deliberately overwritten with the return value) —
        // otherwise a real program using registers this ABI doesn't touch
        // would see them silently corrupted across every syscall.
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Offsets below are all relative to RSP right here, after these
        // 15 pushes (r15 is the most recent push, so it's at [rsp+0]; rax
        // was pushed first, so it's the furthest away).
        "mov rdi, [rsp + 112]", // rax (syscall number) -> dispatch's 1st arg
        "mov rsi, [rsp + 72]",  // rdi (arg1) -> dispatch's 2nd arg
        "mov rdx, [rsp + 80]",  // rsi (arg2) -> dispatch's 3rd arg
        "mov rcx, [rsp + 88]",  // rdx (arg3) -> dispatch's 4th arg
        // SysV requires RSP 16-aligned immediately before `call`, and
        // nothing here guarantees RSP0's own top was 16-aligned to begin
        // with — so rather than assume it, save RSP in a register whose
        // true original value is already safely on the stack (so
        // clobbering the register itself here is harmless), force-align,
        // call, then restore it exactly before touching the stack again.
        "mov r15, rsp",
        "and rsp, -16",
        "call {dispatch}",
        "mov rsp, r15",
        // Overwrite the saved RAX slot with the return value — this is
        // what ends up back in the caller's RAX after the pops below.
        "mov [rsp + 112], rax",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "iretq",
        dispatch = sym dispatch,
    );
}

extern "C" fn dispatch(number: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    match number {
        SYS_WRITE => sys_write(arg1, arg2, arg3),
        SYS_READ => sys_read(arg1, arg2, arg3),
        _ => u64::MAX, // unknown syscall
    }
}

/// write(fd, ptr, len) -> bytes written, or u64::MAX on error. Only
/// fd == 1 (stdout, the VGA console) is supported.
///
/// `ptr`/`len` describe a buffer in the *caller's own* address space.
/// `int 0x80` doesn't change CR3, so at this point it's still whatever the
/// calling thread's own page table is — exactly what's needed to read
/// its buffer correctly, isolated or not. No CR3 juggling needed here at
/// all: println! only ever touches the VGA buffer, a fixed physical
/// address identity-mapped into every address space this kernel builds,
/// never the heap.
///
/// Not validated beyond a length cap: a caller passing a pointer that
/// isn't actually mapped (or not readable) in its own address space will
/// page-fault the kernel, which — with no course-correction beyond
/// panicking — takes the whole kernel down with it. A real
/// `copy_from_user` (checking the mapping first, or handling the fault
/// and returning an error instead of panicking) is exactly the kind of
/// thing a from-scratch kernel adds once it needs to survive a buggy or
/// hostile process; deliberately out of scope for this first pass.
fn sys_write(fd: u64, ptr: u64, len: u64) -> u64 {
    if fd != 1 || ptr == 0 {
        return u64::MAX;
    }
    let len = len.min(1024) as usize;

    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    match core::str::from_utf8(bytes) {
        Ok(s) => crate::print!("{}", s),
        Err(_) => crate::print!("<sys_write: invalid utf-8>"),
    }
    len as u64
}

/// read(fd, ptr, len) -> bytes read (possibly 0 if none are available
/// right now — this never blocks), or u64::MAX on error. Only fd == 0
/// (stdin, decoded keyboard input) is supported.
///
/// Unlike `sys_write`, this needs kernel-owned state: the queue of
/// decoded keystrokes (`task::keyboard`), fed by the keyboard interrupt
/// handler via the same async-task machinery `print_keypresses` uses.
/// That queue lives on the kernel heap, which an isolated caller's own
/// CR3 doesn't map — so, same reasoning as `keyboard_interrupt_handler`
/// (src/interrupts.rs), the kernel's own address space has to be forced
/// for that part. A stack-local buffer stages the result so the switch
/// back to the caller's own CR3 happens *before* touching its buffer.
fn sys_read(fd: u64, ptr: u64, len: u64) -> u64 {
    if fd != 0 || ptr == 0 {
        return 0;
    }
    let len = len.min(256) as usize;
    if len == 0 {
        return 0;
    }

    let mut staged = [0u8; 256];
    let read_count = {
        let (caller_page_table, flags) = Cr3::read();
        let kernel_page_table = scheduler::kernel_page_table();
        let needs_switch = caller_page_table != kernel_page_table;
        if needs_switch {
            unsafe { Cr3::write(kernel_page_table, flags) };
        }

        let mut count = 0;
        while count < len {
            match crate::task::keyboard::try_pop_input_byte() {
                Some(byte) => {
                    staged[count] = byte;
                    count += 1;
                }
                None => break,
            }
        }

        if needs_switch {
            unsafe { Cr3::write(caller_page_table, flags) };
        }
        count
    };

    if read_count > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(staged.as_ptr(), ptr as *mut u8, read_count);
        }
    }
    read_count as u64
}
