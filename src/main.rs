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

use core::panic::PanicInfo;

// Bring println! into scope from our vga_buffer module via lib.rs
use velora_os::println;

// ------------------------------------------------------------------
// KERNEL ENTRY POINT
// ------------------------------------------------------------------

// #[unsafe(no_mangle)] — keep the function name exactly as "_start".
// The linker looks for "_start" by name to know where to begin execution.
// Rust normally mangles names (adds extra info) so we disable that here.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // extern "C" — use C calling conventions, because the bootloader
    // jumps to _start using C conventions, not Rust's.

    // -> ! means this function never returns.
    // There's nowhere to return TO — no parent process, no OS above us.
    // If we returned, the CPU would execute random garbage memory.

    // Print our first message to the VGA screen
    println!("Hello World{}", "!");

    velora_os::init();

    // invoke a breakpoint exception
    x86_64::instructions::interrupts::int3();

    // If we're in test mode, run all the tests now
    #[cfg(test)]
    test_main();

    // Loop forever — the kernel must never stop running
    println!("VeloraOS did not crash");
    loop {}
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
    // Print the panic info to screen so we can see what went wrong.
    // PanicInfo contains the error message and the file/line where it happened.
    println!("{}", info);

    // Loop forever — we can't recover from a kernel panic, just freeze.
    loop {}
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
