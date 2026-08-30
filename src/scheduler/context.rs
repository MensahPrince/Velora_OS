// ============================================================
// scheduler/context.rs
// The raw register-context switch between two kernel threads.
//
// This is deliberately the only unsafe/asm part of the scheduler. Every
// other file only ever calls `switch_to`; nothing else needs to know how a
// context switch actually happens.
// ============================================================

use core::arch::naked_asm;

/// Switch from the currently running thread onto a different one.
///
/// `old_stack_slot` is a pointer to where the *current* stack pointer
/// should be saved (so this thread can be resumed later); `new_stack` is
/// the stack pointer to resume execution from.
///
/// # How this works
/// This behaves like an ordinary function call that simply doesn't return
/// to its caller — instead, `ret` at the end lands wherever the *other*
/// thread left off the last time IT called `switch_to` (or, for a thread
/// that has never run, wherever its fake initial stack frame points, see
/// `scheduler::spawn`). Concretely:
///
/// 1. Six `push`es save the callee-saved registers (the caller-saved ones
///    don't need saving: by the x86-64 SysV ABI, whatever called us is
///    already responsible for not relying on their values surviving a
///    `call`). RFLAGS isn't saved here either — `scheduler::schedule`
///    disables interrupts before every call to this function and decides
///    for itself when to re-enable them, so by the time we get here IF is
///    always already 0; there's nothing for this function to preserve.
/// 2. The current RSP (now pointing at the top of that saved frame) is
///    written through `old_stack_slot` — this is the value that will let
///    this thread resume right here, later.
/// 3. RSP is switched to `new_stack`, pointing at some *other* thread's
///    previously-saved frame (or a fake one, for a brand-new thread).
/// 4. The six registers are popped back off — but now they're that other
///    thread's saved values — and `ret` jumps to whatever return address
///    sits on top of that frame.
///
/// # Safety
/// `old_stack_slot` must be a valid, writable pointer, and `new_stack` must
/// point to a stack frame previously saved by this same function (or one
/// laid out identically by hand, see `scheduler::build_initial_stack`).
/// This must only ever be called with interrupts already disabled and
/// without holding any lock that the resumed thread (or anything running
/// before this thread is resumed again) might also try to acquire — see
/// `scheduler::schedule`.
#[unsafe(naked)]
pub unsafe extern "C" fn switch_to(old_stack_slot: *mut u64, new_stack: u64) {
    naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp", // *old_stack_slot = rsp
        "mov rsp, rsi",   // rsp = new_stack
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    );
}
