// ============================================================
// lib.rs
// This is the library root of Velora_OS.
// It exposes shared functionality used by both main.rs and tests.
// ============================================================

// no_std — we don't have Rust's standard library available.
// In an OS kernel, there's no OS beneath us to provide it.
#![no_std]
// cfg_attr(test, no_main) — when running tests, tell Rust we're providing
// our own entry point (_start) instead of the normal test runner entry point.
#![cfg_attr(test, no_main)]
// custom_test_frameworks — Rust's built-in test framework needs std, which we don't have.
// This feature lets us define our own test runner instead.
#![feature(custom_test_frameworks)]
// abi_x86_interrupt — enables the experimental "x86-interrupt" calling convention.
// Required for defining interrupt handler functions (e.g. breakpoint_handler in interrupts.rs).
// The CPU pushes an InterruptStackFrame automatically; this ABI tells Rust how to handle it.
#![feature(abi_x86_interrupt)]
// test_runner — points Rust to our custom test runner function below.
#![test_runner(crate::test_runner)]
// reexport_test_harness_main — normally the test harness generates a main() function.
// Since we have no_main, we rename it to test_main so we can call it ourselves.
#![reexport_test_harness_main = "test_main"]

// Bring our two modules into scope so the rest of the kernel can use them.
pub mod gdt;
pub mod interrupts;
pub mod serial;
pub mod vga_buffer;
pub mod memory;
pub mod task;
pub mod scheduler;
pub mod userspace;
pub mod syscall;
pub mod elf;
pub mod ata;
pub mod fs;
use core::panic::PanicInfo;


// ------------------------------------------------------------------
// TEST INFRASTRUCTURE
// ------------------------------------------------------------------

// Testable is a trait (a contract) that says:
// "Any type that implements me must have a run() method."
// We use this to give every test function the ability to run itself
// and report its name and result.
pub trait Testable {
    fn run(&self) -> ();
}

// Implement Testable for any type T that is a function (Fn()).
// This means every test function automatically gets the run() method.
impl<T> Testable for T
where
    T: Fn(), // T must be a callable function with no arguments
{
    fn run(&self) {
        // Print the test function's name to serial (your terminal outside QEMU).
        // core::any::type_name::<T>() returns the full name of the function as a string.
        // \t is a tab character for alignment.
        serial_print!("{}...\t", core::any::type_name::<T>());

        // Call the test function itself (self is the function here)
        self();

        // If we got here, the test didn't panic — so it passed!
        serial_println!("[ok]");
    }
}

// test_runner — receives a slice of all test functions and runs them one by one.
// Rust collects all #[test_case] functions and passes them here.
pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test.run(); // calls our Testable::run() above
    }
    // After all tests pass, tell QEMU to exit successfully
    exit_qemu(QemuExitCode::Success);
}

// test_panic_handler — if a test panics, this runs instead of the normal panic handler.
// It reports the failure and exits QEMU with a failure code.
pub fn test_panic_handler(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    hlt_loop() // loop forever — required because -> ! means this never returns
}

// ------------------------------------------------------------------
// TEST ENTRY POINT
// ------------------------------------------------------------------

// This _start is only compiled when running tests (cfg(test)).
// It's our kernel entry point during test runs.
// It calls test_main() which was renamed from the auto-generated test harness main.
#[cfg(test)]
use bootloader::{entry_point, BootInfo};

#[cfg(test)]
entry_point!(test_kernel_main);

#[cfg(test)]
fn test_kernel_main(_boot_info: &'static BootInfo) -> ! {
    // extern "C" because the bootloader calls us using C calling conventions
    test_main(); // run all the tests
    hlt_loop();
}

// Panic handler for test mode.
// When a test panics, this hands off to test_panic_handler above.
#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

// ------------------------------------------------------------------
// QEMU EXIT CODES
// ------------------------------------------------------------------

// These values tell QEMU whether the OS exited successfully or failed.
// We use 0x10 and 0x11 (not 0 and 1) to avoid clashing with QEMU's own internal exit codes.
//
// 0x10 = 0001 0000 = Success
// 0x11 = 0001 0001 = Failed  (one bit different from Success)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)] // store as u32 because the QEMU exit port expects a 32-bit value
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

// exit_qemu — write an exit code to QEMU's special debug exit port (0xf4).
// When QEMU sees a write to 0xf4, it shuts down with the given code.
pub fn exit_qemu(exit_code: QemuExitCode) {
    use x86_64::instructions::port::Port;

    unsafe {
        // Port::new(0xf4) — open a connection to I/O port 0xf4.
        // I/O ports are a different way to talk to hardware (not memory-mapped).
        // 0xf4 is QEMU's "please exit" port.
        let mut port = Port::new(0xf4);

        // Write our exit code to the port.
        // QEMU will see this and shut down.
        // unsafe because directly talking to hardware ports is inherently unsafe.
        port.write(exit_code as u32);
    }
}

/// Load the GDT/IDT and remap the PICs. CPU exceptions (breakpoint, page
/// fault, ...) work immediately after this, since they aren't gated by the
/// interrupt flag. Hardware IRQs (timer, keyboard, ...) stay masked off
/// until `enable_interrupts()` is called separately: anything an ISR might
/// touch — like the heap-allocated keyboard scancode queue — has to exist
/// first, and the heap isn't set up yet at this point in boot.
pub fn init() {
    gdt::init();
    interrupts::init_idt();
    unsafe {
        interrupts::PICS.lock().initialize();
    }
}

/// Unmask hardware interrupts (the `sti` instruction). Call only once
/// everything an ISR could touch — the heap, the keyboard scancode queue —
/// is ready; otherwise a keystroke arriving early can hit an uninitialized
/// resource.
pub fn enable_interrupts() {
    x86_64::instructions::interrupts::enable();
}

pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

extern crate alloc;

pub mod allocator;