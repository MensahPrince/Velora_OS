// ============================================================
// main.rs
// The entry point of Velora_OS.
// This is the first Rust code that runs after the bootloader.
// ============================================================

// no_std — no standard library. We're the OS, there's nothing beneath us.
#![no_std]
// no_main — we're not using Rust's normal main() function.
// The bootloader doesn't call main(), it calls _start() directly.
#![no_main]
// custom_test_frameworks — use our own test runner defined in lib.rs
// instead of Rust's default one (which requires std).
#![feature(custom_test_frameworks)]
// Point to the test runner we defined in lib.rs (velora_os is our crate name)
#![test_runner(velora_os::test_runner)]
// Rename the auto-generated test harness entry point to test_main
// so we can call it ourselves from _start below.
#![reexport_test_harness_main = "test_main"]

use bootloader::{BootInfo, entry_point};
use core::panic::PanicInfo;

// Bring println! into scope from our vga_buffer module via lib.rs
use velora_os::println;

// ------------------------------------------------------------------
// KERNEL ENTRY POINT
// ------------------------------------------------------------------

// #[unsafe(no_mangle)] — keep the function name exactly as "_start".
// The linker looks for "_start" by name to know where to begin execution.
// Rust normally mangles names (adds extra info) so we disable that here.

extern crate alloc;
use alloc::{boxed::Box, vec, vec::Vec, rc::Rc};

use velora_os::memory::BootInfoFrameAllocator;
use x86_64::structures::paging::{FrameAllocator, OffsetPageTable, Page, Size4KiB};

entry_point!(kernel_main);
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    // `memory` module — now exposes `memory::init()` which returns an
    // OffsetPageTable. Importing the whole module keeps call-sites readable.
    use velora_os::memory;
    use x86_64::VirtAddr;
    use velora_os::allocator; // import the new allocator module

    // -> ! means this function never returns.
    // There's nowhere to return TO — no parent process, no OS above us.
    // If we returned, the CPU would execute random garbage memory.

    // Print our first message to the VGA screen
    println!("Welcome to Velora_OS{}", "!");

    // Load the GDT/IDT and remap the PICs. Hardware interrupts (timer,
    // keyboard) stay masked until we explicitly enable them further down —
    // once the heap and the scancode queue that the keyboard ISR feeds are
    // actually ready for it.
    velora_os::init();

    // The bootloader maps all of physical memory starting at
    // `physical_memory_offset`. We wrap that offset in a VirtAddr so the
    // page-table code can convert physical addresses to virtual ones.
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);

    // `memory::init` reads CR3, finds the active Level-4 page table, and
    // wraps it in an `OffsetPageTable`. The mapper implements the `Translate`
    // trait, so we can call `mapper.translate_addr(virt)` instead of doing
    // the 4-level walk manually (that manual version lives in
    // `translate_addr_inner` and is kept for reference).
    

    let mut mapper = unsafe { memory::init(phys_mem_offset) };
    let mut frame_allocator = unsafe { BootInfoFrameAllocator::init(&boot_info.memory_map) };
    // A handful of virtual addresses whose physical mappings we want to print.
    // This exercises the new mapper and confirms the paging setup is correct.

    allocator::init_heap(&mut mapper, &mut frame_allocator).expect("init_heap failed");

    // The heap exists now, so the (heap-allocated) scancode queue and the
    // scheduler's (also heap-backed) ready queue can both be created, and
    // it's then safe to let hardware interrupts — including the timer,
    // which now drives preemptive scheduling — start firing.
    velora_os::task::keyboard::init_queue();
    velora_os::scheduler::init();
    velora_os::enable_interrupts();

    run_bringup_demo(&mut mapper, &mut frame_allocator);

    // Two demo kernel threads that proved the scheduler actually preempts
    // (thread A relying purely on timer preemption, thread B yielding
    // explicitly every iteration) — verified working via a real QEMU boot.
    // Disabled now: left running, they print forever in the background,
    // which just gets in the way of using the kernel normally. Re-enable
    // to sanity-check the scheduler again after touching it.
    #[cfg(not(test))]
    if false {
        velora_os::scheduler::spawn(demo_thread_a);
        velora_os::scheduler::spawn(demo_thread_b);
    }

    // Ring 3 (user-mode) demo: map a small hand-written shellcode page,
    // then spawn a thread that drops into it and runs it at CPL 3 — see
    // src/userspace.rs. Not spawned in test builds, same reasoning as the
    // scheduler demo threads above: it prints in the background, which
    // would race with tests that check exact VGA buffer contents.
    //
    // Disabled for now: this and the isolated demo below both drop a
    // thread into ring 3, and both ring3<->ring0 transitions go through
    // the single shared RSP0 stack (see the TSS setup in src/gdt.rs) —
    // which is only sound with one ring-3 thread at a time. Running both
    // concurrently is under investigation; re-enable once RSP0 is
    // per-thread (or some other fix lands) rather than a single static.
    #[cfg(not(test))]
    if false {
        velora_os::userspace::map_demo_page(&mut mapper, phys_mem_offset, &mut frame_allocator);
        velora_os::scheduler::spawn(velora_os::userspace::run_demo);
    }

    // Real process isolation: the same demo, but running in its own
    // address space rather than the kernel's shared one — see
    // src/userspace.rs and src/memory.rs (`new_address_space`). Proven by
    // checking, right here, in the *kernel's own* page tables, whether the
    // isolated demo's page is visible at all.
    #[cfg(not(test))]
    {
        use x86_64::structures::paging::Translate;

        velora_os::userspace::spawn_isolated_demo(&mut mapper, phys_mem_offset, &mut frame_allocator);

        let isolated_addr = VirtAddr::new(velora_os::userspace::ISOLATED_USER_PAGE_ADDR);
        println!(
            "kernel's own view of the isolated demo's page: {:?} (should be None — \
             it's only mapped in that demo's own address space)",
            mapper.translate_addr(isolated_addr)
        );
    }

    // Commented out while focusing on paging — re-enable to run the test suite.
    #[cfg(test)]
    test_main();

    // A message to prove that the OS is running
    println!("Velora_OS did not crash");

    // Hand off to the cooperative-multitasking executor. It never returns:
    // it polls ready tasks and `hlt`s the CPU whenever there's nothing to
    // do, waking back up on the next interrupt (e.g. a keystroke).
    use velora_os::task::{Task, executor::Executor, keyboard::print_keypresses};
    let mut executor = Executor::new();
    executor.spawn(Task::new(print_keypresses()));
    executor.run();
}

// ------------------------------------------------------------------
// ONE-TIME BOOT DEMO
// ------------------------------------------------------------------

/// Exercises paging (a manual page mapping), the heap allocator (Box, Vec),
/// and Rc reference counting, once, at boot. Not part of the kernel's
/// ongoing behavior — kept out of `kernel_main` so its startup sequence
/// stays readable as more real subsystems (a scheduler, more tasks) land
/// there.
fn run_bringup_demo(
    mapper: &mut OffsetPageTable<'_>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    use velora_os::memory;
    use x86_64::VirtAddr;

    // Map an unused page to the VGA text buffer frame, purely as a demo of
    // `mapper.map_to`. Deliberately NOT the null page (address 0) — mapping
    // page 0 would remove the usual guarantee that a null-pointer write
    // faults instead of silently succeeding.
    let page = Page::containing_address(VirtAddr::new(0xdeadbeaf000));

    // call create_example_mapping to create a mapping for the page
    memory::create_example_mapping(page, mapper, frame_allocator);

    // write the string `New!` to the screen through the new mapping
    let page_ptr: *mut u64 = page.start_address().as_mut_ptr();
    unsafe { page_ptr.offset(400).write_volatile(0x_f021_f077_f065_f04e) };

    // A write to an unmapped address (e.g. 0xdeadbeef) triggers a page
    // fault; with no handler for it, that becomes a double fault, and with
    // no handler for THAT either, a fatal triple fault — QEMU (like most
    // real hardware) reacts to a triple fault by resetting, which is why
    // that used to show up as an endless bootloop. src/interrupts.rs now
    // has real page-fault and double-fault handlers, so this no longer
    // happens; kept here as a note since it's a rite of passage in OS dev.

    //allocate a number on the heap and print it
    let heap_value = Box::new(41);
    println!("Heap_value at {:p}", heap_value);

    //create a dynamically sized vector and print it
    let mut vec = Vec::new();
    for i in 1..500 {
        vec.push(i);
    }

    println!("Vec at {:p}", vec.as_slice());

    // create a reference counted vector -> will be freed when count reaches 0
    let reference_counted = Rc::new(vec![1, 2, 3]);
    let cloned_reference = reference_counted.clone();
    println!("current reference count is {}", Rc::strong_count(&cloned_reference));
    core::mem::drop(reference_counted);
    println!("reference count is {} now", Rc::strong_count(&cloned_reference));
}

// ------------------------------------------------------------------
// SCHEDULER DEMO THREADS
// ------------------------------------------------------------------

/// Relies purely on timer-driven preemption — never calls `yield_now()`.
#[cfg(not(test))]
fn demo_thread_a() -> ! {
    let mut n: u64 = 0;
    loop {
        println!("[thread A] {}", n);
        n += 1;
        for _ in 0..2_000_000 {
            core::hint::spin_loop();
        }
    }
}

/// Gives up its turn voluntarily every iteration, exercising the
/// yield_now() path rather than relying only on the timer.
#[cfg(not(test))]
fn demo_thread_b() -> ! {
    let mut n: u64 = 0;
    loop {
        println!("[thread B] {}", n);
        n += 1;
        for _ in 0..2_000_000 {
            core::hint::spin_loop();
        }
        velora_os::scheduler::yield_now();
    }
}

// ------------------------------------------------------------------
// PANIC HANDLERS
// ------------------------------------------------------------------

// This panic handler runs during normal operation (not tests).
// cfg(not(test)) means "compile this only when NOT running tests".
// When something goes wrong in the kernel, Rust calls this automatically.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    // Disable interrupts so the timer/keyboard handlers can't keep printing
    // and scroll the panic message off screen while we're halted.
    x86_64::instructions::interrupts::disable();
    velora_os::hlt_loop();
}

// This panic handler runs during tests.
// cfg(test) means "compile this only when running tests".
// It hands off to test_panic_handler in lib.rs which reports the failure
// and exits QEMU with a failure code.
#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    velora_os::test_panic_handler(info)
}
