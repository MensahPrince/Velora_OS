// ============================================================
// scheduler/mod.rs
// A preemptive, round-robin scheduler for kernel threads.
//
// This sits *underneath* the cooperative async executor (src/task/), not
// in place of it: threads here have their own real stacks and can be
// interrupted mid-instruction by the timer, the way "real" OS scheduling
// works. In this kernel, the async executor just runs as the body of one
// thread (see kernel_main) — its `print_keypresses` task and friends keep
// working exactly as before, just now preemptible like everything else.
//
// Still ring 0 only: every thread shares the kernel's single address space
// and page table. Real process isolation needs ring 3 execution and a
// separate address space per process on top of this, not instead of it.
// ============================================================

mod context;

use alloc::{alloc::Layout, collections::VecDeque};
use spin::Mutex;
use x86_64::instructions::interrupts;

/// How many kernel threads can exist at once, including the boot thread
/// (id 0). Fixed-size rather than a growable map so nothing here needs to
/// allocate (or worry about a container reshuffling memory) while a switch
/// is in flight.
const MAX_THREADS: usize = 16;

/// 16 KiB per kernel thread. Plenty for the simple demo threads this
/// kernel spawns (a loop, a println!, a spin-wait); revisit if threads
/// start doing deep recursion. Kept modest since the heap itself is only
/// 1 MiB (see src/allocator.rs) — each thread's stack comes out of it.
const STACK_SIZE: usize = 16 * 1024;

pub type ThreadId = usize;

struct Thread {
    /// Saved RSP. Only meaningful while this thread is *not* the one
    /// currently running — `schedule()` updates it right before switching
    /// away, and it becomes stale (and unused) the moment this thread is
    /// resumed.
    stack_pointer: u64,
    /// The thread's dedicated stack. Not read anywhere yet — there's no
    /// thread-exit support to free it — but kept so that adding cleanup
    /// later doesn't need any other bookkeeping threaded through first.
    #[allow(dead_code)]
    stack_base: *mut u8,
    #[allow(dead_code)]
    stack_size: usize,
    /// Consumed once, by `thread_trampoline`, the first time this thread
    /// runs. `None` for the boot thread (id 0), which doesn't run through
    /// the trampoline — it's already executing when `init()` registers it.
    entry: Option<fn() -> !>,
}

// `Thread` holds a raw pointer (`stack_base`), which by default makes it
// !Send. Every access happens through `SCHEDULER`'s spin::Mutex, so it's
// never touched from two places at once.
unsafe impl Send for Thread {}

struct SchedulerState {
    threads: [Option<Thread>; MAX_THREADS],
    ready_queue: VecDeque<ThreadId>,
    current: ThreadId,
}

static SCHEDULER: Mutex<Option<SchedulerState>> = Mutex::new(None);

/// Register the currently executing context as thread 0 and bring the
/// scheduler up. Must be called once, after the heap is ready (the ready
/// queue is heap-allocated) and before `spawn` or `tick`.
pub fn init() {
    let threads: [Option<Thread>; MAX_THREADS] = core::array::from_fn(|i| {
        if i == 0 {
            // The boot thread: no stack to allocate, it's already running
            // on one. `stack_pointer` is never read for it until the first
            // time it's switched *away* from, at which point `schedule`
            // fills in a real value.
            Some(Thread {
                stack_pointer: 0,
                stack_base: core::ptr::null_mut(),
                stack_size: 0,
                entry: None,
            })
        } else {
            None
        }
    });

    interrupts::without_interrupts(|| {
        *SCHEDULER.lock() = Some(SchedulerState {
            threads,
            // Reserved once, up front, so `schedule()` (which runs inside
            // the timer ISR) never needs to grow this — growing would mean
            // calling into the global heap allocator's own spinlock from
            // interrupt context, which could deadlock against a thread
            // that got interrupted mid-allocation elsewhere. At most
            // MAX_THREADS ids are ever queued at once, so this capacity is
            // always enough.
            ready_queue: VecDeque::with_capacity(MAX_THREADS),
            current: 0,
        });
    });
}

/// Spawn a new kernel thread running `entry` (which must never return —
/// there's no thread-exit support yet, see the module docs on `Thread`).
/// It joins the round-robin rotation immediately.
pub fn spawn(entry: fn() -> !) {
    // Disabled for the whole call, not just the SCHEDULER lock: this also
    // allocates the thread's stack, and holding the global allocator's own
    // lock with interrupts enabled would risk the timer ISR's scheduling
    // code trying to lock it too (see the ready_queue capacity note in
    // `init`).
    interrupts::without_interrupts(|| {
        let layout = Layout::from_size_align(STACK_SIZE, 16).unwrap();
        let stack_base = unsafe { alloc::alloc::alloc(layout) };
        assert!(!stack_base.is_null(), "kernel thread stack allocation failed");
        let stack_pointer = unsafe { build_initial_stack(stack_base) };

        let mut guard = SCHEDULER.lock();
        let state = guard
            .as_mut()
            .expect("scheduler::init must be called before spawn");

        let id = state
            .threads
            .iter()
            .position(Option::is_none)
            .expect("thread table full (MAX_THREADS exceeded)");

        state.threads[id] = Some(Thread {
            stack_pointer,
            stack_base,
            stack_size: STACK_SIZE,
            entry: Some(entry),
        });
        state.ready_queue.push_back(id);
    });
}

/// Lay down a fake "already switched away" frame at the top of a fresh
/// stack, so `context::switch_to`'s restore sequence lands in
/// `thread_trampoline` exactly as if resuming a real suspended thread. See
/// `context::switch_to`'s doc comment for the frame layout this mirrors.
///
/// # Safety
/// `stack_base` must point to a live allocation of at least `STACK_SIZE`
/// bytes, 16-byte aligned.
unsafe fn build_initial_stack(stack_base: *mut u8) -> u64 {
    let stack_end = unsafe { stack_base.add(STACK_SIZE) } as u64;

    // SysV requires RSP == 8 (mod 16) when a function is entered via
    // `call` (a 16-aligned RSP, minus the 8 bytes `call` just pushed). We
    // fake that: `frame_top` — where the fake return address lives — sits
    // 16 bytes below the (16-aligned) end of the stack, leaving one 8-byte
    // padding slot above it. `ret` pops that return address and leaves RSP
    // at `frame_top + 8`, i.e. `stack_end - 8`, which is `8 (mod 16)` as
    // required — so `thread_trampoline` sees a correctly aligned stack.
    let frame_top = stack_end - 16;

    // High address to low address, matching the order switch_to's restore
    // sequence consumes them: return address (what `ret` jumps to) first,
    // then the six callee-saved GPRs, ending at r15 — whose address
    // becomes the saved stack pointer. (No RFLAGS slot: switch_to doesn't
    // save/restore it — see its doc comment — so there's nothing to fake
    // here either.)
    let frame: [u64; 7] = [
        thread_trampoline as *const () as u64, // "return address"
        0,                                  // rbp
        0,                                  // rbx
        0,                                  // r12
        0,                                  // r13
        0,                                  // r14
        0,                                  // r15
    ];
    let dst = frame_top as *mut u64;
    for (i, &word) in frame.iter().enumerate() {
        unsafe { dst.sub(i).write(word) };
    }

    frame_top - (frame.len() as u64 - 1) * 8 // address of the r15 slot
}

/// Where every freshly spawned thread starts executing. Reached via
/// `context::switch_to`'s `ret`, not a normal call — so it can't take
/// arguments; it looks up its own entry point in the scheduler state
/// instead.
extern "C" fn thread_trampoline() -> ! {
    let entry = interrupts::without_interrupts(|| {
        let mut guard = SCHEDULER.lock();
        let state = guard.as_mut().expect("scheduler not initialized");
        state.threads[state.current]
            .as_mut()
            .and_then(|t| t.entry.take())
            .expect("thread_trampoline entered for a thread with no entry point")
    });

    // A brand-new thread lands here with interrupts still disabled:
    // `schedule()` always disables them before a switch, and normally
    // re-enables them itself once the switched-away thread resumes inside
    // `schedule()` again later — but a thread that has never run before
    // doesn't resume inside `schedule()` at all, it starts right here, so
    // nothing has turned them back on yet. Do that now, before running
    // real thread code.
    interrupts::enable();
    entry();
}

/// Called from the timer interrupt handler. Rotates to the next ready
/// thread, if there is one to switch to.
pub fn tick() {
    schedule();
}

/// Voluntarily give up the rest of this thread's turn. Unlike `tick()`,
/// this can be called from ordinary (non-interrupt) code.
pub fn yield_now() {
    schedule();
}

/// Pick the next ready thread and switch to it, if there is one besides
/// the one already running.
///
/// Interrupts are deliberately *not* restored immediately after
/// `switch_to` the way a plain `without_interrupts(...)` call would: this
/// function doesn't actually return to its caller until this same thread
/// is scheduled back in, possibly much later, so the restore has to happen
/// *after* that point — see the comment below `switch_to` for why.
fn schedule() {
    let interrupts_were_enabled = interrupts::are_enabled();
    interrupts::disable();

    let mut guard = SCHEDULER.lock();
    let state = match guard.as_mut() {
        Some(state) => state,
        // Called before `init()` (shouldn't happen once boot reaches the
        // point of enabling interrupts) — nothing to schedule yet.
        None => {
            drop(guard);
            if interrupts_were_enabled {
                interrupts::enable();
            }
            return;
        }
    };

    let next = match state.ready_queue.pop_front() {
        Some(id) => id,
        None => {
            // No other thread wants to run right now.
            drop(guard);
            if interrupts_were_enabled {
                interrupts::enable();
            }
            return;
        }
    };
    let previous = state.current;
    state.ready_queue.push_back(previous);
    state.current = next;

    let old_stack_slot = {
        let previous_thread = state.threads[previous]
            .as_mut()
            .expect("current thread missing from thread table");
        &mut previous_thread.stack_pointer as *mut u64
    };
    let new_stack = state.threads[next]
        .as_ref()
        .expect("next thread missing from thread table")
        .stack_pointer;

    // Unlock before the switch: holding a spin::Mutex guard across
    // switch_to would deadlock the first time anything tried to lock
    // SCHEDULER again (the guard's Drop — its unlock — would never run,
    // since switch_to leaves via a raw `ret`, never returning here to run
    // the rest of this scope). Sound only because interrupts stay disabled
    // (see above) for the rest of this function: nothing can mutate
    // `threads` in the gap between dropping the guard and using these raw
    // pointers.
    drop(guard);

    unsafe {
        context::switch_to(old_stack_slot, new_stack);
    }

    // Execution only reaches here once this exact thread has been
    // scheduled back in — that can happen much later, and via a
    // completely different call to `schedule()` than the one that switched
    // it away. Restore interrupts to what *this* thread had before it
    // called schedule(): for a voluntary yield_now() that's normally
    // enabled; for a tick()-triggered preemption it's already disabled,
    // and should stay that way here — we're still conceptually inside that
    // original timer ISR call, and its own eventual `iretq` (not this) is
    // what correctly restores this thread's true pre-interrupt state.
    if interrupts_were_enabled {
        interrupts::enable();
    }
}
