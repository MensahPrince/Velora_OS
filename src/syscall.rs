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

use crate::elf;
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
pub const SYS_SPAWN: u64 = 5;
pub const SYS_WAIT: u64 = 6;

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
        SYS_SPAWN => sys_spawn(arg1, arg2),
        SYS_WAIT => sys_wait(arg1),
        // `scheduler::exit_current_thread()` returns `!`, not `u64` — it
        // never comes back here to produce a value, the same way it never
        // comes back to `entry`'s own `call {dispatch}` either (see that
        // naked_asm's doc comment). Diverging is fine as a match arm: `!`
        // coerces to whatever type the other arms settle on.
        SYS_EXIT => scheduler::exit_current_thread(),
        _ => u64::MAX, // unknown syscall
    }
}

/// Whether `[ptr, ptr + len)` is entirely mapped in the calling thread's
/// own address space — `need_write` selects which direction
/// (`memory::user_range_mapped`; `int 0x80` never switches CR3, so the
/// *currently active* table it checks is already exactly the calling
/// thread's own, isolated or not). The shared check behind
/// `copy_from_user`/`copy_to_user`, and also called directly by
/// `sys_read_stdin`/`sys_read_file` *before* they do anything
/// irreversible (popping a keystroke, advancing an open file's read
/// position) — checking only after would mean a bad `ptr` silently
/// discards real data instead of failing before it's ever touched.
fn user_range_ok(ptr: u64, len: usize, need_write: bool) -> bool {
    if ptr == 0 {
        return false;
    }
    match VirtAddr::try_new(ptr) {
        Ok(addr) => memory::user_range_mapped(memory::physical_memory_offset(), addr, len, need_write),
        Err(_) => false,
    }
}

/// Copy `out.len()` bytes from the calling thread's own address space at
/// `ptr` into `out`. Kills the calling thread (`scheduler::
/// kill_current_thread`) instead of returning an error if `ptr` is null,
/// isn't a canonical address at all, or any page the range covers isn't
/// mapped `PRESENT | USER_ACCESSIBLE` (`user_range_ok`) — the same class
/// of mistake a real OS answers with `SIGSEGV`, not something worth
/// handing back to the offending program as an ordinary return value to
/// maybe notice.
fn copy_from_user(ptr: u64, out: &mut [u8]) {
    if !user_range_ok(ptr, out.len(), false) {
        scheduler::kill_current_thread("syscall argument pointer not mapped for read");
    }
    unsafe {
        core::ptr::copy_nonoverlapping(ptr as *const u8, out.as_mut_ptr(), out.len());
    }
}

/// The write-direction counterpart to `copy_from_user`: copy all of `data`
/// into the calling thread's own address space at `ptr`, killing the
/// calling thread under the same conditions `user_range_ok` rejects (with
/// `need_write: true`, so a read-only mapping counts as rejected too).
fn copy_to_user(ptr: u64, data: &[u8]) {
    if !user_range_ok(ptr, data.len(), true) {
        scheduler::kill_current_thread("syscall argument pointer not mapped for write");
    }
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
    }
}

/// write(fd, ptr, len) -> bytes written, or u64::MAX on error. Only
/// fd == 1 (stdout, the VGA console) is supported. A `ptr`/`len` that
/// isn't actually mapped in the caller's own address space doesn't
/// produce an error return at all — it kills the calling thread, via
/// `copy_from_user`.
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
    copy_from_user(ptr, &mut staged[..len]);

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
/// Every other fd (including 1, stdout — write-only) is an error. A `ptr`
/// that isn't actually mapped in the caller's own address space doesn't
/// produce an error return at all — it kills the calling thread, via
/// `sys_read_stdin`/`sys_read_file`'s own `user_range_ok` check.
fn sys_read(fd: u64, ptr: u64, len: u64) -> u64 {
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
/// Validates `ptr` (`user_range_ok`) *before* popping anything off the
/// keyboard queue: those bytes are gone once popped, so checking only
/// after would mean a bad `ptr` loses real input to a kill that happens
/// to come after it's already been consumed, rather than before anything
/// is touched at all.
fn sys_read_stdin(ptr: u64, len: usize) -> u64 {
    if !user_range_ok(ptr, len, true) {
        scheduler::kill_current_thread("sys_read: destination pointer not mapped for write");
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
        copy_to_user(ptr, &staged[..read_count]);
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
/// position, so a bad `ptr` is caught before it can skip past real file
/// contents that were never actually delivered anywhere.
fn sys_read_file(fd: u64, ptr: u64, len: usize) -> u64 {
    if !user_range_ok(ptr, len, true) {
        scheduler::kill_current_thread("sys_read: destination pointer not mapped for write");
    }

    let mut staged = [0u8; 256];
    match scheduler::read_open_file(fd, &mut staged[..len]) {
        Some(count) => {
            if count > 0 {
                copy_to_user(ptr, &staged[..count]);
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
/// space, checked via `copy_from_user` (which kills the calling thread
/// rather than returning an error if `path_ptr` isn't actually mapped) —
/// capped at a small length rather than an arbitrary one.
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
    copy_from_user(path_ptr, &mut staged_path[..path_len]);
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

/// spawn(path_ptr, path_len) -> pid, or u64::MAX if the path isn't valid
/// UTF-8, doesn't name a file `fs::read_file` can find, or that file
/// doesn't parse as a well-formed ELF64 executable (`elf::load`). Looks
/// `path` up on the FAT16 disk, loads it into a brand-new isolated address
/// space, and spawns a new ring-3 thread running it (`scheduler::
/// spawn_user`) — this is what actually lets a running program launch
/// another one, the piece a shell needs that no other syscall here
/// provides; every process before this one only ever came from kernel
/// boot code calling `elf::load`/`scheduler::spawn_isolated` directly.
///
/// Not real `fork()`: this never duplicates the calling process's own
/// memory the way a true fork would (needed for e.g. a process that wants
/// to keep running its own code in a child copy of itself) — it only ever
/// loads and runs a *different* program from a path, closer to
/// `posix_spawn`. That's deliberate: a shell needs to launch other
/// programs, not clone itself, and real `fork` would additionally need
/// copy-on-write address-space duplication this kernel has no machinery
/// for at all yet.
fn sys_spawn(path_ptr: u64, path_len: u64) -> u64 {
    if path_len == 0 || path_len > 255 {
        return u64::MAX;
    }
    let path_len = path_len as usize;

    let mut staged_path = [0u8; 255];
    copy_from_user(path_ptr, &mut staged_path[..path_len]);
    let path = match core::str::from_utf8(&staged_path[..path_len]) {
        Ok(s) => s,
        Err(_) => return u64::MAX,
    };

    // Same reasoning as sys_open's own CR3 handling: fs::read_file,
    // elf::load, and scheduler::spawn_user all touch the kernel heap
    // and/or the global frame allocator, none of which an isolated
    // caller's own CR3 maps.
    let (caller_page_table, flags) = Cr3::read();
    let kernel_page_table = scheduler::kernel_page_table();
    let needs_switch = caller_page_table != kernel_page_table;
    if needs_switch {
        unsafe { Cr3::write(kernel_page_table, flags) };
    }
    let pid = spawn_from_path(path);
    if needs_switch {
        unsafe { Cr3::write(caller_page_table, flags) };
    }

    pid.unwrap_or(u64::MAX)
}

/// The kernel-CR3-only part of `sys_spawn`: look `path` up on disk, parse
/// it as an ELF, and spawn a new isolated ring-3 thread running it. Split
/// out so `sys_spawn` can bracket the whole thing in exactly one CR3
/// switch out to the kernel's own address space and back, rather than the
/// file lookup, the ELF parse, and the actual spawn each separately
/// reasoning about which table needs to be active.
fn spawn_from_path(path: &str) -> Option<scheduler::Pid> {
    let data = crate::fs::read_file(path)?;
    let physical_memory_offset = memory::physical_memory_offset();
    let (mut isolated_mapper, loaded) =
        elf::load(&data, physical_memory_offset, &mut memory::GlobalFrameAllocator)?;

    // No long-lived mapper of its own to reach for here, unlike
    // kernel_main — memory::current_mapper builds one fresh over whatever
    // table is already active (which this function requires to be the
    // kernel's own, per sys_spawn's CR3 switch above).
    let mut kernel_mapper = unsafe { memory::current_mapper(physical_memory_offset) };
    Some(scheduler::spawn_user(
        loaded.entry,
        loaded.stack_top,
        loaded.page_table,
        &mut kernel_mapper,
        &mut isolated_mapper,
        &mut memory::GlobalFrameAllocator,
    ))
}

/// wait(pid) -> 0 once the thread `pid` refers to (from `sys_spawn`'s
/// return value) has finished — however it finished, a clean `exit()` or
/// an involuntary `scheduler::kill_current_thread` — or u64::MAX
/// immediately if `pid` doesn't refer to a thread that's alive right now.
/// No exit status: this kernel's own `exit_current_thread` doesn't record
/// one anywhere, so there's nothing here to hand back beyond "it's gone
/// now" — a real Unix `wait`'s exit-code/signal reporting is deliberately
/// out of scope for this first pass.
///
/// No real blocking/wait-queue primitive exists yet, so this just polls
/// `scheduler::thread_alive` in a loop, yielding this thread's own turn
/// between checks — from a ring-3 caller's own perspective this still
/// looks like an ordinary blocking call, since nothing about the polling
/// is visible outside this one syscall.
fn sys_wait(pid: u64) -> u64 {
    if !scheduler::thread_alive(pid) {
        return u64::MAX;
    }
    while scheduler::thread_alive(pid) {
        scheduler::yield_now();
    }
    0
}
