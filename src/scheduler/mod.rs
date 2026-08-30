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
// Threads are ring 0 only by default, but a thread can instead be given its
// own address space (`spawn_isolated`) — a genuinely separate set of page
// tables, not just a lower privilege level — which `schedule()` switches
// CR3 to whenever that thread runs. See src/userspace.rs for what actually
// runs inside one.
// ============================================================

mod context;

use alloc::alloc::Layout;
use spin::Mutex;
use x86_64::{
    VirtAddr,
    instructions::interrupts,
    registers::control::Cr3,
    structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageTableFlags, PhysFrame, Size4KiB,
    },
};

/// How many kernel threads can exist at once, including the boot thread
/// (id 0). Fixed-size rather than a growable map so nothing here needs to
/// allocate (or worry about a container reshuffling memory) while a switch
/// is in flight.
const MAX_THREADS: usize = 16;

/// 16 KiB per kernel thread. Plenty for the simple demo threads this
/// kernel spawns (a loop, a println!, a spin-wait); revisit if threads
/// start doing deep recursion. Kept modest since the heap itself is only
/// 1 MiB (see src/allocator.rs) — each thread's stack comes out of it.
/// A multiple of 4096: stacks are allocated page-aligned (see `spawn`),
/// which `spawn_isolated` relies on to map a precise, non-overlapping
/// range of whole pages into an isolated address space.
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
    /// `Some(l4_frame)` for a thread spawned via `spawn_isolated` — its own
    /// dedicated address space, switched to via CR3 whenever this thread
    /// runs. `None` means "the shared kernel address space every ordinary
    /// thread uses" (`SchedulerState::kernel_page_table`).
    page_table: Option<PhysFrame>,
}

/// A fixed-capacity FIFO of thread ids — deliberately not a heap-backed
/// `VecDeque`. `schedule()` runs from inside the timer ISR, which can fire
/// with *any* thread's address space active (interrupts don't switch CR3
/// on their own — see `context::switch_to`'s doc comment), including an
/// isolated one that doesn't map the kernel heap at all. A `VecDeque`'s
/// struct (pointer/len/cap) would still live in this static (so, always
/// reachable), but the actual buffer it points to would not be — so
/// touching it while an isolated address space is active would fault
/// exactly like any other access to unmapped memory. Every element instead
/// lives inline, right here, in the same static as everything else
/// `schedule()` touches.
struct ReadyQueue {
    ids: [ThreadId; MAX_THREADS],
    head: usize,
    len: usize,
}

impl ReadyQueue {
    const fn new() -> Self {
        ReadyQueue {
            ids: [0; MAX_THREADS],
            head: 0,
            len: 0,
        }
    }

    fn push_back(&mut self, id: ThreadId) {
        assert!(self.len < MAX_THREADS, "ready queue full");
        let index = (self.head + self.len) % MAX_THREADS;
        self.ids[index] = id;
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<ThreadId> {
        if self.len == 0 {
            return None;
        }
        let id = self.ids[self.head];
        self.head = (self.head + 1) % MAX_THREADS;
        self.len -= 1;
        Some(id)
    }
}

// `Thread` holds a raw pointer (`stack_base`), which by default makes it
// !Send. Every access happens through `SCHEDULER`'s spin::Mutex, so it's
// never touched from two places at once.
unsafe impl Send for Thread {}

struct SchedulerState {
    threads: [Option<Thread>; MAX_THREADS],
    ready_queue: ReadyQueue,
    current: ThreadId,
    /// The L4 frame that was active when `init()` ran — i.e. the shared
    /// address space every ordinary (non-isolated) thread runs under.
    /// `schedule()` switches CR3 back to this for any thread whose own
    /// `page_table` is `None`.
    kernel_page_table: PhysFrame,
}

static SCHEDULER: Mutex<Option<SchedulerState>> = Mutex::new(None);

/// Register the currently executing context as thread 0 and bring the
/// scheduler up. Must be called once, before `spawn` or `tick`.
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
                page_table: None,
            })
        } else {
            None
        }
    });

    interrupts::without_interrupts(|| {
        let (kernel_page_table, _) = Cr3::read();
        *SCHEDULER.lock() = Some(SchedulerState {
            threads,
            ready_queue: ReadyQueue::new(),
            current: 0,
            kernel_page_table,
        });
    });
}

/// The shared kernel address space's L4 frame — the one every ordinary
/// (non-isolated) thread runs under. Interrupt handlers that touch
/// heap-backed state (e.g. the keyboard handler, src/interrupts.rs) need
/// this: such a handler can run with *any* thread's address space active,
/// since interrupts don't care what was interrupted, so it has to force
/// its way back to an address space where the heap is actually mapped
/// before touching anything heap-backed.
pub fn kernel_page_table() -> PhysFrame {
    interrupts::without_interrupts(|| {
        SCHEDULER
            .lock()
            .as_ref()
            .expect("scheduler not initialized")
            .kernel_page_table
    })
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
        let layout = Layout::from_size_align(STACK_SIZE, 4096).unwrap();
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
            page_table: None,
        });
        state.ready_queue.push_back(id);
    });
}

/// Like `spawn`, but the new thread gets its own address space
/// (`page_table`, an L4 frame built by `memory::new_address_space`)
/// instead of the shared kernel one — `schedule()` switches CR3 to it
/// whenever this thread runs. See src/userspace.rs for the actual ring-3
/// program that runs inside one.
///
/// `kernel_mapper` is the caller's own (shared, currently active) mapper;
/// `isolated_mapper` is the one `memory::new_address_space` handed back
/// alongside `page_table`, for mapping pages into the new space before
/// anything runs under it.
pub fn spawn_isolated(
    entry: fn() -> !,
    page_table: PhysFrame,
    kernel_mapper: &mut OffsetPageTable,
    isolated_mapper: &mut OffsetPageTable,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    interrupts::without_interrupts(|| {
        let layout = Layout::from_size_align(STACK_SIZE, 4096).unwrap();
        let stack_base = unsafe { alloc::alloc::alloc(layout) };
        assert!(!stack_base.is_null(), "kernel thread stack allocation failed");
        let stack_pointer = unsafe { build_initial_stack(stack_base) };

        // This thread's kernel-mode stack lives in the shared kernel heap,
        // which the isolated address space otherwise can't see at all —
        // that's the whole point of it being isolated. But its own
        // ring-0-side code (thread_trampoline, and whatever setup it does
        // before dropping to ring 3) still needs it, and so does resuming
        // correctly if a timer interrupt preempts it before it gets that
        // far (see the CR3 handling in `schedule()` below). So the exact
        // same physical frames get mapped at the exact same virtual
        // addresses in the isolated table too — kernel-only, not
        // USER_ACCESSIBLE, so ring-3 code running in this same address
        // space still can't reach it, only ring-0 code under this CR3 can.
        let stack_start = VirtAddr::from_ptr(stack_base);
        let first_page = Page::<Size4KiB>::containing_address(stack_start);
        let page_count = STACK_SIZE / 4096;
        for i in 0..page_count as u64 {
            let page = first_page + i;
            let frame = kernel_mapper
                .translate_page(page)
                .expect("thread stack page vanished right after being allocated");
            unsafe {
                isolated_mapper
                    .map_to(
                        page,
                        frame,
                        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                        frame_allocator,
                    )
                    .expect("failed to share a thread stack page into its isolated address space")
                    .flush();
            }
        }

        let mut guard = SCHEDULER.lock();
        let state = guard
            .as_mut()
            .expect("scheduler::init must be called before spawn_isolated");

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
            page_table: Some(page_table),
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
    let next_thread = state.threads[next]
        .as_ref()
        .expect("next thread missing from thread table");
    let new_stack = next_thread.stack_pointer;
    let new_page_table = next_thread
        .page_table
        .unwrap_or(state.kernel_page_table)
        .start_address()
        .as_u64();

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
        context::switch_to(old_stack_slot, new_stack, new_page_table);
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
