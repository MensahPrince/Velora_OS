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

use crate::memory;
use crate::scheduler;
use core::arch::naked_asm;
use x86_64::VirtAddr;
use x86_64::registers::control::Cr3;

pub const SYS_WRITE: u64 = 0;
pub const SYS_READ: u64 = 1;
pub const SYS_EXIT: u64 = 2;
pub const SYS_OPEN: u64 = 3;
pub const SYS_CLOSE: u64 = 4;

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
        SYS_OPEN => sys_open(arg1, arg2),
        SYS_CLOSE => sys_close(arg1),
        // `scheduler::exit_current_thread()` returns `!`, not `u64` — it
        // never comes back here to produce a value, the same way it never
        // comes back to `entry`'s own `call {dispatch}` either (see that
        // naked_asm's doc comment). Diverging is fine as a match arm: `!`
        // coerces to whatever type the other arms settle on.
        SYS_EXIT => scheduler::exit_current_thread(),
        _ => u64::MAX, // unknown syscall
    }
}

/// Copy `out.len()` bytes from the calling thread's own address space at
/// `ptr` into `out`, or return `None` — instead of blindly trusting `ptr`
/// and letting a bad one page-fault (and, with no course-correction beyond
/// `panic!`, take the whole kernel down with it) — if `ptr` is null, isn't
/// a canonical address at all (`VirtAddr::try_new`), or any page the range
/// covers isn't mapped `PRESENT | USER_ACCESSIBLE` for the *currently
/// active* page table (`memory::user_range_mapped`; `int 0x80` never
/// switches CR3, so that's already exactly the calling thread's own table,
/// isolated or not).
fn copy_from_user(ptr: u64, out: &mut [u8]) -> Option<()> {
    if ptr == 0 {
        return None;
    }
    let addr = VirtAddr::try_new(ptr).ok()?;
    if !memory::user_range_mapped(memory::physical_memory_offset(), addr, out.len(), false) {
        return None;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(ptr as *const u8, out.as_mut_ptr(), out.len());
    }
    Some(())
}

/// Whether `[ptr, ptr + len)` is safe to write `len` bytes into in the
/// calling thread's own address space — the check half of `copy_to_user`,
/// pulled out on its own so a caller with side effects to perform first
/// (`sys_read_stdin`/`sys_read_file`, which otherwise pop a keystroke or
/// advance an open file's read position before ever finding out the
/// destination was bad) can validate the destination *before* doing
/// anything that can't be undone, rather than losing that data to a
/// doomed copy.
fn user_write_ok(ptr: u64, len: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    match VirtAddr::try_new(ptr) {
        Ok(addr) => memory::user_range_mapped(memory::physical_memory_offset(), addr, len, true),
        Err(_) => false,
    }
}

/// The write-direction counterpart to `copy_from_user`: copy all of `data`
/// into the calling thread's own address space at `ptr`, or `None` if
/// `user_write_ok` rejects the range.
fn copy_to_user(ptr: u64, data: &[u8]) -> Option<()> {
    if !user_write_ok(ptr, data.len()) {
        return None;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
    }
    Some(())
}

/// write(fd, ptr, len) -> bytes written, or u64::MAX on error (including a
/// `ptr`/`len` that isn't actually mapped in the caller's own address
/// space — see `copy_from_user`). Only fd == 1 (stdout, the VGA console)
/// is supported.
///
/// `int 0x80` doesn't change CR3, so at this point it's still whatever the
/// calling thread's own page table is — exactly what `copy_from_user`
/// needs to check and then read `ptr`'s buffer correctly, isolated or not.
/// No further CR3 juggling needed here at all: `println!` only ever
/// touches the VGA buffer, a fixed physical address identity-mapped into
/// every address space this kernel builds, never the heap.
fn sys_write(fd: u64, ptr: u64, len: u64) -> u64 {
    if fd != 1 {
        return u64::MAX;
    }
    let len = len.min(1024) as usize;

    let mut staged = [0u8; 1024];
    if copy_from_user(ptr, &mut staged[..len]).is_none() {
        return u64::MAX;
    }

    match core::str::from_utf8(&staged[..len]) {
        Ok(s) => crate::print!("{}", s),
        Err(_) => crate::print!("<sys_write: invalid utf-8>"),
    }
    len as u64
}

/// read(fd, ptr, len) -> bytes read (possibly 0 if none are available right
/// now, for stdin, or if an open file is exhausted — this never blocks), or
/// u64::MAX on error. fd == 0 is stdin (decoded keyboard input); fd >=
/// `scheduler::FIRST_FILE_FD` is a file this thread opened via `sys_open`.
/// Every other fd (including 1, stdout — write-only) is an error.
fn sys_read(fd: u64, ptr: u64, len: u64) -> u64 {
    if ptr == 0 {
        return u64::MAX;
    }
    let len = len.min(256) as usize;
    if len == 0 {
        return 0;
    }

    if fd == 0 {
        return sys_read_stdin(ptr, len);
    }
    if fd >= scheduler::FIRST_FILE_FD {
        return sys_read_file(fd, ptr, len);
    }
    u64::MAX
}

/// The stdin case of `sys_read`, unchanged from before `sys_open`/file
/// reads existed: kernel-owned state (the queue of decoded keystrokes,
/// `task::keyboard`, fed by the keyboard interrupt handler via the same
/// async-task machinery `print_keypresses` uses) lives on the kernel heap,
/// which an isolated caller's own CR3 doesn't map — so, same reasoning as
/// `keyboard_interrupt_handler` (src/interrupts.rs), the kernel's own
/// address space has to be forced for that part. A stack-local buffer
/// stages the result so the switch back to the caller's own CR3 happens
/// *before* touching its buffer.
///
/// Validates `ptr` (`user_write_ok`) *before* popping anything off the
/// keyboard queue: those bytes are gone once popped, so checking only
/// after would mean a bad `ptr` silently discards real input instead of
/// just failing cleanly with nothing consumed.
fn sys_read_stdin(ptr: u64, len: usize) -> u64 {
    if !user_write_ok(ptr, len) {
        return u64::MAX;
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

    if read_count > 0 && copy_to_user(ptr, &staged[..read_count]).is_none() {
        return u64::MAX;
    }
    read_count as u64
}

/// The open-file case of `sys_read`: copy up to `len` bytes from the
/// calling thread's own `fd` (`scheduler::read_open_file`, which handles
/// the same CR3 juggling `sys_read_stdin` does above, since an open file's
/// buffered bytes are heap-backed too) into its buffer at `ptr`.
///
/// Same reasoning as `sys_read_stdin`'s own up-front check: `ptr` is
/// validated before `read_open_file` ever advances the file's read
/// position, so a bad `ptr` fails cleanly rather than silently skipping
/// past real file contents that were never actually delivered anywhere.
fn sys_read_file(fd: u64, ptr: u64, len: usize) -> u64 {
    if !user_write_ok(ptr, len) {
        return u64::MAX;
    }

    let mut staged = [0u8; 256];
    match scheduler::read_open_file(fd, &mut staged[..len]) {
        Some(count) => {
            if count > 0 && copy_to_user(ptr, &staged[..count]).is_none() {
                return u64::MAX;
            }
            count as u64
        }
        None => u64::MAX,
    }
}

/// open(path_ptr, path_len) -> fd, or u64::MAX if the path isn't valid
/// UTF-8, isn't representable as an 8.3 name, doesn't exist on the FAT16
/// disk (`fs::read_file`), or the calling thread already has
/// `scheduler::MAX_OPEN_FILES` other files open. Reads the *entire* file
/// into a kernel-owned buffer immediately — `fs::read_file` has no
/// partial/streaming read of its own — so later `read(fd, ...)` calls just
/// copy out of that buffer.
///
/// `path_ptr`/`path_len` describe a buffer in the caller's own address
/// space, checked via `copy_from_user` — capped at a small length rather
/// than an arbitrary one.
fn sys_open(path_ptr: u64, path_len: u64) -> u64 {
    if path_len == 0 || path_len > 255 {
        return u64::MAX;
    }
    let path_len = path_len as usize;

    // Copied onto the stack — mapped under every address space this kernel
    // ever builds, unlike `path_ptr` itself, which points into the
    // *caller's* own — before the CR3 switch below leaves that behind.
    // `fs::read_file` needs both this path *and* the kernel heap (for the
    // `Vec<u8>` it hands back), and those two requirements can't be
    // satisfied under the same CR3 for an isolated caller, so the path has
    // to be captured first, independent of whichever address space is
    // active once `fs::read_file` actually runs.
    let mut staged_path = [0u8; 255];
    if copy_from_user(path_ptr, &mut staged_path[..path_len]).is_none() {
        return u64::MAX;
    }
    let path = match core::str::from_utf8(&staged_path[..path_len]) {
        Ok(s) => s,
        Err(_) => return u64::MAX,
    };

    // Same reasoning (and the same pattern) as `sys_read_stdin`'s own CR3
    // handling: `fs::read_file` touches the kernel heap, which an isolated
    // caller's own CR3 doesn't map.
    let (caller_page_table, flags) = Cr3::read();
    let kernel_page_table = scheduler::kernel_page_table();
    let needs_switch = caller_page_table != kernel_page_table;
    if needs_switch {
        unsafe { Cr3::write(kernel_page_table, flags) };
    }
    let data = crate::fs::read_file(path);
    if needs_switch {
        unsafe { Cr3::write(caller_page_table, flags) };
    }

    match data {
        Some(data) => scheduler::open_file(data).unwrap_or(u64::MAX),
        None => u64::MAX,
    }
}

/// close(fd) -> 0 on success, u64::MAX if `fd` wasn't a file the calling
/// thread currently had open. Frees the file's buffered contents
/// immediately (`scheduler::close_file`) rather than waiting for the
/// thread to exit — purely a courtesy to a caller that wants to free up a
/// slot in its own `scheduler::MAX_OPEN_FILES`-sized table without exiting;
/// nothing about correctness depends on a program ever calling this, since
/// `reap_zombie` frees every still-open file at exit regardless.
fn sys_close(fd: u64) -> u64 {
    if scheduler::close_file(fd) { 0 } else { u64::MAX }
}
