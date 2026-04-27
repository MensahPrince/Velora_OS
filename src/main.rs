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

entry_point!(kernel_main);
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    // `memory` module — now exposes `memory::init()` which returns an
    // OffsetPageTable. Importing the whole module keeps call-sites readable.
    use velora_os::memory;
    // `Translate` is the trait that gives OffsetPageTable its
    // `translate_addr` method. It must be in scope for the method to resolve.
    use x86_64::structures::paging::Page;
    use x86_64::{VirtAddr/*, structures::paging::Translate*/ };
    // use x86_64::structures::paging::Size4KiB;
    use velora_os::memory::BootInfoFrameAllocator;
    use velora_os::allocator; // import the new allocator module

    // -> ! means this function never returns.
    // There's nowhere to return TO — no parent process, no OS above us.
    // If we returned, the CPU would execute random garbage memory.

    // Print our first message to the VGA screen
    println!("Welcome to Velora_OS{}", "!");

    // Initialise CPU exception/interrupt handling (IDT, GDT, PICS).
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
    // map an unused page
    let page = Page::containing_address(VirtAddr::new(0));
    // Create a mapping for the virtual address 0xdeadbeef000
    // let page = Page::containing_address(VirtAddr::new(0xdeadbeaf000));

    // call create_example_mapping to create a mapping for the page
    memory::create_example_mapping(page, &mut mapper, &mut frame_allocator);

    // write the string `New!` to the screen through the new mapping
    let page_ptr: *mut u64 = page.start_address().as_mut_ptr();
    unsafe { page_ptr.offset(400).write_volatile(0x_f021_f077_f065_f04e) };

    /*
    let addresses = [
        // identity-mapped VGA text buffer
        0xb8000,
        // a kernel code page
        0x201008,
        // a kernel stack page
        0x0100_0020_1a10,
        // the start of the physical-memory mapping (should resolve to phys 0)
        boot_info.physical_memory_offset,
    ];

    for &address in &addresses {
        let virt = VirtAddr::new(address);
        // `translate_addr` walks the page tables via the OffsetPageTable
        // abstraction. Returns Some(PhysAddr) if mapped, None if not.
        let phys = mapper.translate_addr(virt);
        println!("{:?} -> {:?}", virt, phys);
    }
    */

    //The commented code below this comment was for simulating
    // a page fault.
    // We used an unsafe to write to an invalid memory location address 0xdeadbeef
    // The virtual address is not mapped to any physical addr in the page tables.
    // This will cause a page fault.
    // As observed, when the kernel is started, it enters an endless
    // bootloop. The reason for the bootloop is as follows.
    // 1. The CPU tries to write to 0xdeadbeef which causes a page fault.
    // 2. The CPU looks at the corresponding entru in in the IDT and sees that
    //    there is no handler and a double fault occurs.
    // 3. The CPU loos at the IDT entry of the double fault handler,
    //    but this entry does not specify a handler function either. Thus, a triple fault occurs.
    // 4. A triple fault is fatal. QEMU reacts to it like most real hardware
    //    by resetting the system. This causes the endless bootloop.
    //
    // The code below is for simulating a page fault.
    //
    //unsafe {
    //    *(0xdeadbeef as *mut u8) = 42;
    //};

    // The code at the end of this comment is for simulating
    // a stack overflow.
    // fn stack_overflow() {
    //    stack_overflow();
    //}

    // Trigger a stackoverflow
    //stack_overflow();

    // Commented out while focusing on paging — re-enable to test the IDT
    // breakpoint exception handler.
    // x86_64::instructions::interrupts::int3();


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
    
    // Commented out while focusing on paging — re-enable to run the test suite.
    #[cfg(test)]
    test_main();

    // Loop forever — the kernel must never stop running
    // A message to prove that the OS is running
    println!("Velora_OS did not crash");
    velora_os::hlt_loop();
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
