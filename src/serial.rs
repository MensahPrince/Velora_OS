// ============================================================
// serial.rs
// Handles output to the serial port (0x3F8).
// Serial output goes to YOUR terminal outside QEMU —
// this is how tests report results back to you.
//
// VGA  → text appears inside the QEMU window (user facing)
// Serial → text appears in your terminal (developer/testing)
// ============================================================

use lazy_static::lazy_static;
use spin::Mutex;

// uart_16550 is a crate that abstracts the UART serial hardware.
// UART 16550 is a very old but universal serial chip — QEMU emulates it.
use uart_16550::SerialPort;


// ------------------------------------------------------------------
// GLOBAL SERIAL PORT
// ------------------------------------------------------------------

// lazy_static! creates SERIAL1 as a global that initializes on first use.
// We can't initialize it at compile time because it requires runtime setup (init()).
lazy_static! {
    // Mutex ensures only one thing writes to serial at a time,
    // preventing garbled output if two things try to write simultaneously.
    pub static ref SERIAL1: Mutex<SerialPort> = {
        // SerialPort::new(0x3F8) — 0x3F8 is the standard I/O port address for
        // the first serial port (COM1) on x86 hardware. QEMU emulates this.
        // unsafe because we're directly accessing hardware ports.
        let mut serial_port = unsafe { SerialPort::new(0x3F8) };

        // init() sets up the serial port hardware — configures baud rate,
        // data bits, stop bits, etc. Must be called before any writing.
        serial_port.init();

        Mutex::new(serial_port)
    };
}

// _print — the actual function that writes to the serial port.
// Both serial_print! and serial_println! macros call this.
// #[doc(hidden)] hides it from documentation — it's an internal detail.
#[doc(hidden)]
pub fn _print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;

    // Lock the serial port (so nothing else can write at the same time)
    // then write the formatted arguments to it.
    // .expect() panics with a message if the write fails.
    SERIAL1
        .lock()
        .write_fmt(args)
        .expect("Printing to serial failed");
}


// ------------------------------------------------------------------
// MACROS
// ------------------------------------------------------------------

/// Prints to the host through the serial interface.
/// Output appears in your terminal outside QEMU, not on the QEMU screen.
#[macro_export]
macro_rules! serial_print {
    // ($($arg:tt)*) matches anything you type inside serial_print!(...)
    // format_args!() builds a formatted argument object without allocating memory.
    // $crate ensures this resolves to our crate regardless of where the macro is called.
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*));
    };
}

/// Prints to the host through the serial interface, appending a newline.
/// Three rules to handle different ways you might call it:
#[macro_export]
macro_rules! serial_println {
    // Rule 1: serial_println!() — no arguments, just print a newline
    () => ($crate::serial_print!("\n"));

    // Rule 2: serial_println!("hello") — just a string, append \n to it
    // concat! glues two strings together at compile time: "hello" + "\n" = "hello\n"
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));

    // Rule 3: serial_println!("value is {}", x) — format string + arguments
    // concat! appends \n to the format string, then passes all args along
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(
        concat!($fmt, "\n"), $($arg)*));
}