// ============================================================
// userspace.rs
// Two demos, in increasing order of how real they are:
//
// - `run_demo`: proves ring 3 (user-mode) execution works at all — a
//   hand-written shellcode page invoked via IRETQ, calling back into the
//   kernel through a software interrupt (int 0x80, src/interrupts.rs).
//   Still shares the kernel's own page tables, just at a lower privilege
//   level (CPL 3 instead of CPL 0) — no actual isolation.
// - `run_isolated_demo`: the same shellcode, but running in its own
//   address space (see `memory::new_address_space`), switched to via CR3
//   whenever its thread runs (`scheduler::spawn_isolated`). This is what
//   real process isolation actually rests on: the kernel's own view of
//   memory (see `prove_isolation` in main.rs) can't see this page at all,
//   even though the isolated thread runs from it just fine.
// ============================================================

use crate::{gdt, memory, scheduler};
use core::arch::asm;
use x86_64::{
    VirtAddr,
    instructions::segmentation::{DS, ES, FS, GS, Segment},
    structures::paging::{FrameAllocator, Mapper, OffsetPageTable, Page, PageTableFlags, Size4KiB},
};

/// Where the demo's code+stack page lives. Arbitrary but deliberately far
/// from every other mapping this kernel makes (the heap at
/// 0x4444_4444_0000, the earlier paging demo at 0xdeadbeaf000): that keeps
/// its whole page-table chain (P4 down to P1) unmapped beforehand, so
/// `map_to` below creates every level fresh and propagates
/// `USER_ACCESSIBLE` all the way down. Reusing an address whose upper
/// levels already exist from an earlier, kernel-only mapping would need
/// those levels re-flagged too — `map_to` only sets flags on levels it
/// creates, not ones it finds already there.
const USER_PAGE_ADDR: u64 = 0x5555_5555_0000;

/// Where the *isolated* demo's page lives — in its own address space, so
/// reusing `USER_PAGE_ADDR` would have been just as safe, but a distinct
/// address (in a P4 slot nothing else in this kernel ever uses) keeps the
/// two demos easy to tell apart in diagnostics like `prove_isolation`.
pub const ISOLATED_USER_PAGE_ADDR: u64 = 0x6000_0000_0000;

// Hand-assembled machine code rather than a compiled Rust function: there's
// no reliable way to know how many bytes a compiled function occupies in
// order to copy "just it" into the user page, so the bytes are written out
// directly instead.
//   cd 80   int 0x80   (x5 — enough to clearly show up as repeated
//                        "got a syscall" lines on screen)
//   eb fe   jmp $       (infinite loop: jumps 2 bytes back, i.e. to itself)
#[rustfmt::skip]
static USER_SHELLCODE: [u8; 12] = [
    0xcd, 0x80,
    0xcd, 0x80,
    0xcd, 0x80,
    0xcd, 0x80,
    0xcd, 0x80,
    0xeb, 0xfe,
];

/// Map a demo code+stack page at `addr` in `mapper` and copy the shellcode
/// into it. The code lives at the start of the page; the stack (unused by
/// this shellcode — it never pushes anything) grows down from the page's
/// end, sharing the same page since this demo is small enough that the two
/// can't realistically collide.
///
/// The shellcode is written through `physical_memory_offset + frame`, not
/// through `addr` itself: `addr` is only guaranteed to be mapped once
/// `mapper`'s own table is the *active* one, which for an isolated address
/// space (`spawn_isolated_demo`) isn't true yet at this point — the whole
/// point of `OffsetPageTable`-based setup is that every table this kernel
/// builds shares the same offset window, so a frame belonging to it is
/// still reachable through that alias regardless of whether its table is
/// loaded into CR3 yet.
fn map_shellcode_page(
    mapper: &mut OffsetPageTable<'_>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    physical_memory_offset: VirtAddr,
    addr: u64,
) {
    let page = Page::containing_address(VirtAddr::new(addr));
    let frame = frame_allocator
        .allocate_frame()
        .expect("no physical frames left for the ring 3 demo page");
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    unsafe {
        mapper
            .map_to(page, frame, flags, frame_allocator)
            .expect("failed to map the ring 3 demo page")
            .flush();
    }

    let code_ptr = (physical_memory_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
    unsafe {
        core::ptr::copy_nonoverlapping(USER_SHELLCODE.as_ptr(), code_ptr, USER_SHELLCODE.len());
    }
}

/// Map the demo's code+stack page and copy the shellcode into it, in the
/// kernel's own (shared) address space. Call once, from kernel_main (which
/// already has a mapper and frame allocator on hand), before spawning
/// `run_demo` as a scheduler thread.
pub fn map_demo_page(
    mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    map_shellcode_page(mapper, frame_allocator, physical_memory_offset, USER_PAGE_ADDR);
}

/// Build a fresh, isolated address space, map the (identical) demo
/// shellcode into it at `ISOLATED_USER_PAGE_ADDR`, and spawn a thread that
/// drops into it — that thread's page table is this new, separate one, not
/// the kernel's own, so it runs genuinely isolated from everything else in
/// this kernel (see the module docs). `kernel_mapper` is the caller's own
/// (shared) mapper, needed so the new thread's kernel-mode stack can be
/// shared into the isolated table too (see `scheduler::spawn_isolated`).
pub fn spawn_isolated_demo(
    kernel_mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    let (l4_frame, mut isolated_mapper) =
        unsafe { memory::new_address_space(physical_memory_offset, frame_allocator) };

    map_shellcode_page(
        &mut isolated_mapper,
        frame_allocator,
        physical_memory_offset,
        ISOLATED_USER_PAGE_ADDR,
    );

    scheduler::spawn_isolated(
        run_isolated_demo,
        l4_frame,
        kernel_mapper,
        &mut isolated_mapper,
        frame_allocator,
    );
}

/// Spawned as a scheduler thread (`scheduler::spawn(run_demo)`). Drops to
/// ring 3 and runs the shellcode `map_demo_page` placed there, which loops
/// forever after a few `int 0x80` calls — so, like `thread_trampoline`,
/// this function's own body never really executes past the call that
/// takes us there.
pub fn run_demo() -> ! {
    let entry = VirtAddr::new(USER_PAGE_ADDR);
    let stack_top = VirtAddr::new(USER_PAGE_ADDR + 4096 - 16); // top of the same page, 16-aligned

    unsafe {
        enter_ring3(entry, stack_top);
    }
}

/// Spawned via `spawn_isolated_demo`, which sets up this thread's own
/// address space before it ever runs. Otherwise identical to `run_demo` —
/// it's the address space it runs under (not this function) that makes it
/// isolated.
pub fn run_isolated_demo() -> ! {
    let entry = VirtAddr::new(ISOLATED_USER_PAGE_ADDR);
    let stack_top = VirtAddr::new(ISOLATED_USER_PAGE_ADDR + 4096 - 16);

    unsafe {
        enter_ring3(entry, stack_top);
    }
}

/// Drop from ring 0 to ring 3 by hand-building the frame `iretq` expects
/// (SS, RSP, RFLAGS, CS, RIP, pushed in that order) and executing it.
/// `iretq` doesn't "return" here in the normal sense — from this point on
/// the CPU is running at CPL 3, executing whatever's at `entry`.
///
/// # Safety
/// `entry` and `stack_top` must point into a page mapped PRESENT |
/// USER_ACCESSIBLE (and, since it also serves as the stack, WRITABLE) —
/// see `map_demo_page`.
unsafe fn enter_ring3(entry: VirtAddr, stack_top: VirtAddr) -> ! {
    let (code_selector, data_selector) = gdt::user_selectors();

    unsafe {
        // CS and SS get set by `iretq` itself, from the frame pushed
        // below — but DS/ES/FS/GS aren't touched by iretq, so they'd
        // otherwise keep holding kernel (DPL 0) selectors, which ring 3
        // code isn't allowed to use. Loading them here, while still at
        // CPL 0, is valid (a CPL-0 load of an RPL-3 selector into a data
        // segment register is permitted) and is the standard fix.
        DS::set_reg(data_selector);
        ES::set_reg(data_selector);
        FS::set_reg(data_selector);
        GS::set_reg(data_selector);

        asm!(
            "push {ss}",
            "push {stack}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) u64::from(data_selector.0),
            stack = in(reg) stack_top.as_u64(),
            rflags = in(reg) 0x202u64, // IF (bit 9) set; bit 1 is reserved-as-1
            cs = in(reg) u64::from(code_selector.0),
            rip = in(reg) entry.as_u64(),
            options(noreturn),
        );
    }
}
