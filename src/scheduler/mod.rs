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

use crate::gdt;
use crate::memory;
use alloc::alloc::Layout;
use alloc::vec::Vec;
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
    /// The thread's dedicated stack — read back by `reap_zombie()`, once
    /// this thread has exited, to free it.
    stack_base: *mut u8,
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
    /// The fixed top of this thread's own kernel-mode stack — unlike
    /// `stack_pointer`, this never changes once the thread is spawned.
    /// `schedule()` writes it into the TSS's RSP0 field
    /// (`gdt::set_rsp0`) on every switch, for every thread, not just
    /// ring-3-capable ones: harmless for a thread that never enters ring 3
    /// (RSP0 just goes unused for it), but means each thread that *does*
    /// gets its own privilege-transition stack instead of every ring-3
    /// thread sharing one — see the module docs on `gdt::set_rsp0` for why
    /// that sharing was a real bug. `0` for the boot thread (id 0), which
    /// has no kernel-allocated stack of its own and is never expected to
    /// enter ring 3.
    kernel_stack_top: u64,
    /// This thread's own open files (`syscall::SYS_OPEN`/`SYS_READ`/
    /// `SYS_CLOSE`) — per-thread rather than one shared table, so an
    /// isolated process can't see or exhaust another's file descriptors,
    /// matching the isolation this kernel already enforces for memory.
    /// Each `Some` slot's index (offset by `FIRST_FILE_FD`) *is* the fd a
    /// ring-3 caller was handed back. Dropped automatically — freeing
    /// whatever `Vec` each open file buffered — when `Thread` itself is
    /// dropped at the end of `reap_zombie`, by which point CR3 is already
    /// forced back to the shared kernel table (see that function), so the
    /// heap these `Vec`s are backed by is guaranteed mapped.
    open_files: [Option<OpenFile>; MAX_OPEN_FILES],
}

/// A file `syscall::SYS_OPEN` has already read in full from `fs::read_file`
/// — this kernel's filesystem driver has no partial/streaming read of its
/// own, so the whole thing is buffered up front, and `SYS_READ` just slices
/// out of it, advancing `offset` as it goes.
struct OpenFile {
    data: Vec<u8>,
    offset: usize,
}

/// How many files a single thread can have open at once — small and fixed,
/// same reasoning as `MAX_THREADS`: nothing here needs to grow, so nothing
/// here needs to allocate a resizable container just to hold a handful of
/// slots.
pub const MAX_OPEN_FILES: usize = 4;

/// The lowest fd `syscall::SYS_OPEN` will ever hand back — 0 and 1 stay
/// permanently reserved for stdin/stdout (`syscall::sys_read`/`sys_write`),
/// so a real open file's fd never collides with either.
pub const FIRST_FILE_FD: u64 = 2;

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
    /// Set by `exit_current_thread()` to the thread it just switched away
    /// from for good — its slot in `threads` is still occupied (so its
    /// `stack_base`/`stack_size` are on hand) but it will never run again.
    /// `reap_zombie()` frees it and clears this the next time *any* other
    /// thread reaches a scheduling decision — never here, since a thread
    /// can't free the stack it's still executing on. At most one pending
    /// zombie ever exists: `reap_zombie()` runs at the top of both
    /// `schedule()` and `exit_current_thread()`, so nothing new can be
    /// switched away from until the previous one is cleared.
    zombie: Option<ThreadId>,
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
                kernel_stack_top: 0,
                open_files: core::array::from_fn(|_| None),
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
            zombie: None,
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

/// Run `f` with mutable access to the *currently running* thread's own
/// state, having first forced CR3 to the shared kernel address space (and
/// restored whatever was active before, once `f` returns) — the shared
/// precondition every file-descriptor accessor below needs:
/// `Thread::open_files` holds heap-backed `Vec`s, and an isolated caller's
/// own CR3 doesn't map the kernel heap at all (same reasoning as
/// `reap_zombie`'s own CR3 handling, and `syscall::sys_read`'s existing
/// keyboard-queue case this mirrors). SCHEDULER's own lock is taken and
/// released within this call, not held across it.
fn with_current_thread<R>(f: impl FnOnce(&mut Thread) -> R) -> R {
    interrupts::without_interrupts(|| {
        let (caller_page_table, flags) = Cr3::read();
        let mut guard = SCHEDULER.lock();
        let state = guard.as_mut().expect("scheduler not initialized");
        let needs_switch = caller_page_table != state.kernel_page_table;
        if needs_switch {
            unsafe { Cr3::write(state.kernel_page_table, flags) };
        }

        let thread = state.threads[state.current]
            .as_mut()
            .expect("current thread missing from thread table");
        let result = f(thread);

        if needs_switch {
            unsafe { Cr3::write(caller_page_table, flags) };
        }
        result
    })
}

/// Buffer `data` — the full contents of a file `fs::read_file` already
/// read — as a newly open file in the *currently running* thread's own
/// descriptor table, and return the fd assigned to it, or `None` if that
/// table (`MAX_OPEN_FILES`) is already full. Reached from
/// `syscall::sys_open`, once `fs::read_file` has already done the actual
/// disk work; this just takes ownership of the result and hands back a
/// handle a ring-3 caller can pass to later `read`/`close` calls.
pub fn open_file(data: Vec<u8>) -> Option<u64> {
    with_current_thread(|thread| {
        let slot = thread.open_files.iter().position(Option::is_none)?;
        thread.open_files[slot] = Some(OpenFile { data, offset: 0 });
        Some(slot as u64 + FIRST_FILE_FD)
    })
}

/// Copy up to `buf.len()` bytes out of the currently running thread's open
/// file `fd`, starting wherever the last `read_open_file` call for this
/// same fd left off, and advance that position by however much was
/// actually copied. Returns the number of bytes copied (0 once the file is
/// exhausted — this never blocks, there's nothing left to wait for), or
/// `None` if `fd` isn't a file this thread currently has open.
pub fn read_open_file(fd: u64, buf: &mut [u8]) -> Option<usize> {
    with_current_thread(|thread| {
        let slot = fd.checked_sub(FIRST_FILE_FD)? as usize;
        let file = thread.open_files.get_mut(slot)?.as_mut()?;
        let remaining = &file.data[file.offset..];
        let count = remaining.len().min(buf.len());
        buf[..count].copy_from_slice(&remaining[..count]);
        file.offset += count;
        Some(count)
    })
}

/// Close the currently running thread's open file `fd`, freeing its
/// buffered contents immediately rather than waiting for the thread to
/// exit. Returns whether `fd` was actually an open file to begin with.
pub fn close_file(fd: u64) -> bool {
    with_current_thread(|thread| {
        let Some(slot) = fd.checked_sub(FIRST_FILE_FD) else {
            return false;
        };
        match thread.open_files.get_mut(slot as usize) {
            Some(entry @ Some(_)) => {
                *entry = None;
                true
            }
            _ => false,
        }
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
            kernel_stack_top: stack_base as u64 + STACK_SIZE as u64,
            open_files: core::array::from_fn(|_| None),
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
            kernel_stack_top: stack_base as u64 + STACK_SIZE as u64,
            open_files: core::array::from_fn(|_| None),
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

/// Terminate the calling thread for good: remove it from the round-robin
/// rotation, switch to another ready thread, and (once it's safe — see
/// `reap_zombie`) free its kernel stack and reuse its slot in the thread
/// table. Callable directly by kernel-mode thread bodies, or reached from
/// ring 3 via the syscall ABI (`syscall::SYS_EXIT` — see src/syscall.rs);
/// either way this is the only place that actually implements it.
///
/// Also frees the physical frames backing an isolated thread's own address
/// space — its L4 table, and whatever `elf::load`/
/// `userspace::map_shellcode_page` mapped into it — via
/// `memory::free_address_space`, once it's safe to (see `reap_zombie`).
/// Reclaiming the kernel stack and thread-table slot is what matters most
/// in practice — it's what makes the slot reusable at all, which is what
/// would otherwise make every process this kernel ever ran a one-way trip
/// through `MAX_THREADS` — but without also freeing an isolated thread's
/// address space, every isolated process would instead be a one-way trip
/// through physical memory itself.
///
/// # Panics
/// If called by the boot thread (id 0 — `kernel_main` never calls this,
/// so this should be unreachable) or if no other thread is left in the
/// ready queue to switch into (unreachable in practice: the boot thread
/// stays in the rotation for the life of the kernel, so there's always at
/// least one other thread for any *other* thread to exit into).
pub fn exit_current_thread() -> ! {
    reap_zombie();

    interrupts::disable();
    let mut guard = SCHEDULER.lock();
    let state = guard.as_mut().expect("scheduler not initialized");

    let id = state.current;
    assert_ne!(id, 0, "the boot thread can't exit");

    let next = state
        .ready_queue
        .pop_front()
        .expect("exit_current_thread: no other thread left to run");
    state.current = next;
    // Not pushed back into ready_queue — that omission is what actually
    // removes this thread from rotation for good.
    state.zombie = Some(id);

    let old_stack_slot = {
        let dying_thread = state.threads[id]
            .as_mut()
            .expect("current thread missing from thread table");
        // Never read again (this thread is never resumed), but switch_to
        // unconditionally writes through this pointer, so it still has to
        // point somewhere valid.
        &mut dying_thread.stack_pointer as *mut u64
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
    let new_rsp0 = next_thread.kernel_stack_top;

    unsafe {
        gdt::set_rsp0(VirtAddr::new(new_rsp0));
    }

    // Same reasoning as schedule()'s own drop(guard): switch_to leaves via
    // a raw `ret` that never returns here, so a held guard would never
    // unlock.
    drop(guard);

    unsafe {
        context::switch_to(old_stack_slot, new_stack, new_page_table);
    }

    // Unlike schedule()'s call to switch_to, this one is never resumed —
    // this thread's slot is a zombie now, permanently absent from
    // ready_queue, so nothing will ever switch back into it.
    unreachable!("exit_current_thread: a thread that already exited was resumed");
}

/// If a previous call to `exit_current_thread()` left a thread's slot
/// pending cleanup, free its kernel stack (and, if it was an isolated
/// thread, its own address space) and clear the slot now. Safe to call
/// unconditionally from here: reaching a scheduling decision at all means
/// the *previous* zombie's own `switch_to` call already handed control away
/// for good, so nothing is still executing on the stack (or under the
/// address space) this is about to free.
///
/// Runs as its own short lock scope, separate from `schedule()`'s and
/// `exit_current_thread()`'s own — same reason `spawn()`'s allocation
/// happens before it takes `SCHEDULER`'s lock: the global allocator has
/// its own internal lock, and there's no reason to hold two at once
/// longer than necessary.
fn reap_zombie() {
    let reaped: Option<(Thread, PhysFrame)> = interrupts::without_interrupts(|| {
        let mut guard = SCHEDULER.lock();
        let state = guard.as_mut().expect("scheduler not initialized");
        let zombie_id = state.zombie.take()?;
        let dead = state.threads[zombie_id].take()?;
        Some((dead, state.kernel_page_table))
    });

    let Some((thread, kernel_page_table)) = reaped else {
        return;
    };

    // Whichever thread was actually running when this function got called
    // (not the zombie itself — it was already switched away from, in an
    // earlier call) might have been an isolated one, meaning CR3 right now
    // could be pointing at an address space that doesn't map the kernel
    // heap at all (see `memory::new_address_space`) — and both the stack
    // deallocation below and `memory::free_address_space` touch the heap
    // (the allocator's own free list, and — for the latter — its internal
    // `Vec`-backed frame free list too). Forcing CR3 back to the shared
    // kernel address space first makes that safe unconditionally; it's a
    // no-op (beyond a redundant TLB flush) whenever the running thread
    // wasn't isolated to begin with. Sound because every thread's own
    // kernel stack — this one included, whatever it's currently running on
    // — is mapped identically under every address space this kernel ever
    // builds (`scheduler::spawn_isolated` maps it in specifically so this
    // kind of switch is always safe), so nothing about the code or stack
    // still executing right here becomes unreachable.
    unsafe { Cr3::write(kernel_page_table, Cr3::read().1) };

    // Computed before the stack itself is freed below, purely as a range of
    // *addresses* — nothing here dereferences it. Passed on to
    // `memory::free_address_space` so it can recognize (and skip) the leaf
    // frames of this exact range wherever they're also mapped into the
    // thread's own isolated address space — see that function's doc comment
    // on `borrowed_data_range` for why: they're the same physical frames
    // `alloc::alloc::dealloc`, right below, is about to hand back to the
    // heap allocator, not `frame_allocator`'s to reclaim a second time.
    let stack_addr = thread.stack_base as u64;
    let stack_range = stack_addr..stack_addr + thread.stack_size as u64;

    let layout = Layout::from_size_align(thread.stack_size, 4096).unwrap();
    unsafe { alloc::alloc::dealloc(thread.stack_base, layout) };

    if let Some(page_table) = thread.page_table {
        unsafe {
            memory::free_address_space(
                page_table,
                memory::physical_memory_offset(),
                stack_range,
                &mut memory::GlobalFrameAllocator,
            );
        }
    }
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
    reap_zombie();

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
    let new_rsp0 = next_thread.kernel_stack_top;

    // Unlike the CR3 write (handled inside switch_to itself — see its doc
    // comment for why), updating RSP0 doesn't change what's currently
    // accessible, so there's no ordering hazard in doing it here, as
    // plain Rust, before the actual switch.
    unsafe {
        gdt::set_rsp0(VirtAddr::new(new_rsp0));
    }

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
