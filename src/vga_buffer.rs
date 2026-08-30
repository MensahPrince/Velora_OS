// ============================================================
// vga_buffer.rs
// This module handles all screen output for Velora_OS.
// It talks directly to VGA hardware at memory address 0xb8000.
// ============================================================

// Volatile ensures the compiler never skips our writes to VGA memory.
// Without this, the compiler might see "nothing reads this" and delete our writes.
use volatile::Volatile;

// fmt gives us Rust's formatting system (the thing that powers println!)
use core::fmt;

// Mutex is a lock. Only one thing can write to the screen at a time.
// spin::Mutex is a special version that works without an OS — it just
// keeps trying ("spinning") until the lock is free.
use spin::Mutex;

// lazy_static lets us create a global variable that initializes at runtime
// instead of compile time. We need this because our Writer contains a
// raw pointer (0xb8000) which Rust can't set up at compile time.
use lazy_static::lazy_static;

// ------------------------------------------------------------------
// COLOR SYSTEM
// ------------------------------------------------------------------

// #[allow(dead_code)] — Rust warns you if you define something and never use it.
// We define all 16 colors but might not use all of them, so we silence the warning.
#[allow(dead_code)]
// #[derive(...)] — Rust auto-generates these abilities for our Color type:
//   Debug     → lets us print it with {:?} for debugging
//   Clone     → lets us make a copy with .clone()
//   Copy      → lets Rust copy it automatically (since it's just a number)
//   PartialEq → lets us compare with ==
//   Eq        → stronger version of PartialEq
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// #[repr(u8)] — store each Color variant as a u8 (1 byte).
// This matters because VGA hardware expects colors as numbers 0-15.
// Without this, Rust might store the enum differently.
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

// ColorCode holds the full color byte — both foreground and background packed together.
// Remember: the color byte is 8 bits:
//   bits 0-3 → foreground color (4 bits = 16 colors)
//   bits 4-6 → background color (3 bits = 8 colors)
//   bit  7   → blink
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// #[repr(transparent)] — makes ColorCode have the exact same memory layout as u8.
// This means ColorCode(5u8) takes up exactly 1 byte, just like a raw u8 would.
// We need this so ScreenChar's two fields sit perfectly side by side in memory.
#[repr(transparent)]
struct ColorCode(u8);

impl ColorCode {
    fn new(foreground: Color, background: Color) -> ColorCode {
        // We need to pack both colors into one byte.
        // background goes in the upper 4 bits, foreground in the lower 4 bits.
        //
        // Example: foreground = Red (4 = 0100), background = Black (0 = 0000)
        //
        // Step 1: shift background left by 4 bits
        //   0000 → becomes → 0000 0000 (no change since black is 0)
        //
        // Step 2: OR it with foreground
        //   0000 0000
        // | 0000 0100  (Red = 4)
        // = 0000 0100  → final color byte
        //
        // Another example: foreground = White (15 = 1111), background = Blue (1 = 0001)
        //   background << 4 = 0001 0000
        //   foreground      = 0000 1111
        //   OR result       = 0001 1111  → blue background, white text
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}

// ------------------------------------------------------------------
// SCREEN CHARACTER — one cell on the screen
// ------------------------------------------------------------------

// ScreenChar represents a single character cell on screen.
// Each cell is exactly 2 bytes:
//   byte 1 → the character (ASCII)
//   byte 2 → the color code (foreground + background + blink)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// #[repr(C)] — lay out fields in the exact order written, like C does.
// Without this, Rust might reorder the fields for optimization,
// which would break things because VGA hardware expects char first, color second.
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,   // the character to display
    color_code: ColorCode, // its color
}

// ------------------------------------------------------------------
// THE BUFFER — the full screen (25 rows × 80 columns)
// ------------------------------------------------------------------

// These constants define screen dimensions.
// VGA text mode is always 25 rows tall and 80 columns wide.
const BUFFER_HEIGHT: usize = 25;
const BUFFER_WIDTH: usize = 80;

// Buffer represents the actual VGA memory at 0xb8000.
// It's a 2D array of ScreenChars — one per screen cell.
// Volatile<ScreenChar> wraps each cell so the compiler never optimizes away our writes.
#[repr(transparent)] // same memory layout as its single field (the 2D array)
struct Buffer {
    chars: [[Volatile<ScreenChar>; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

// ------------------------------------------------------------------
// THE WRITER — our "marker" that writes to the screen
// ------------------------------------------------------------------

// Writer keeps track of where we are on screen and handles all writing.
// Think of it as a person holding a marker at a specific position on the whiteboard.
pub struct Writer {
    column_position: usize, // which column we're currently at (0-79)
    color_code: ColorCode,  // what color we're writing in
    buffer: &'static mut Buffer, // the whiteboard we're writing on (lives at 0xb8000)
                            // 'static means this reference is valid for the entire program runtime
}

impl Writer {
    // write_byte — write a single character to the screen
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            // If the byte is a newline character, move to the next line
            b'\n' => self.new_line(),

            // Backspace: step the column back and blank the cell there.
            // Only handles the current line — there's no record of how long
            // the previous line was, so backspacing past column 0 is simply
            // a no-op rather than wrapping up to the row above.
            0x08 => {
                if self.column_position > 0 {
                    self.column_position -= 1;
                    let row = BUFFER_HEIGHT - 1;
                    let col = self.column_position;
                    let blank = ScreenChar {
                        ascii_character: b' ',
                        color_code: self.color_code,
                    };
                    self.buffer.chars[row][col].write(blank);
                }
            }

            // For any other byte, write it to the screen
            byte => {
                // If we've reached the end of the line (column 80), wrap to next line
                if self.column_position >= BUFFER_WIDTH {
                    self.new_line();
                }

                // Always write to the last row (row 24).
                // new_line() shifts everything up, so the bottom row is always "current".
                let row = BUFFER_HEIGHT - 1;
                let col = self.column_position;

                let color_code = self.color_code;

                // Write the ScreenChar (character + color) to the buffer.
                // .write() is from Volatile — it ensures the compiler keeps this write.
                self.buffer.chars[row][col].write(ScreenChar {
                    ascii_character: byte,
                    color_code,
                });

                // Move the marker one step forward
                self.column_position += 1;
            }
        }
    }

    // write_string — write a whole string one character at a time.
    // Iterating by `char` (not `byte`) matters for non-ASCII text: a
    // multi-byte UTF-8 codepoint is one logical character and should turn
    // into a single ■ placeholder, not one placeholder per encoded byte.
    pub fn write_string(&mut self, s: &str) {
        for c in s.chars() {
            match c {
                // Only write printable ASCII characters (space=0x20 to tilde=0x7e), newlines,
                // and backspace. VGA hardware only understands ASCII + code page 437.
                ' '..='~' | '\n' | '\u{8}' => self.write_byte(c as u8),

                // For anything outside that range (like non-ASCII characters),
                // print ■ (0xfe) as a placeholder — VGA can't display them.
                _ => self.write_byte(0xfe),
            }
        }
    }

    // new_line — scroll the screen up by one row and clear the bottom row
    fn new_line(&mut self) {
        // Go through every row starting from row 1 (skip row 0 — it scrolls off screen).
        // Copy each row's content into the row above it.
        // Result: everything moves up one row, and row 0 disappears.
        for row in 1..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                let character = self.buffer.chars[row][col].read();
                self.buffer.chars[row - 1][col].write(character);
            }
        }

        // Clear the bottom row so it's blank and ready for new text
        self.clear_row(BUFFER_HEIGHT - 1);

        // Reset column position to start of the line
        self.column_position = 0;
    }

    // clear_row — fill an entire row with blank space characters
    fn clear_row(&mut self, row: usize) {
        // A blank cell is just a space character with the current color
        let blank = ScreenChar {
            ascii_character: b' ', // space
            color_code: self.color_code,
        };

        // Overwrite every column in the row with a blank
        for col in 0..BUFFER_WIDTH {
            self.buffer.chars[row][col].write(blank);
        }
    }
}

// ------------------------------------------------------------------
// FORMATTING SUPPORT — makes println! work
// ------------------------------------------------------------------

// By implementing fmt::Write for Writer, we're telling Rust:
// "Writer knows how to accept formatted text."
//
// The contract: we provide write_str(), and Rust gives us write_fmt() for free.
// write_fmt() is what powers the write!/println! macros.
//
// Chain: println!() → format_args!() → write_fmt() → write_str() → write_string() → write_byte()
impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Just hand off to our existing write_string method
        self.write_string(s);
        // Ok(()) means "success, nothing to return" — VGA writes never fail
        Ok(())
    }
}

// ------------------------------------------------------------------
// GLOBAL WRITER — one shared Writer for the whole kernel
// ------------------------------------------------------------------

// lazy_static! creates a global variable that initializes the first time it's accessed,
// not at compile time. We need this because:
//   1. Rust can't convert raw pointers (0xb8000) to references at compile time
//   2. We need the Writer to exist for the entire program lifetime
lazy_static! {
    // Mutex wraps Writer so only one piece of code can write to the screen at a time.
    // Without Mutex, two things could write simultaneously and corrupt the output.
    pub static ref WRITER: Mutex<Writer> = Mutex::new(Writer {
        column_position: 0, // start at the leftmost column
        color_code: ColorCode::new(Color::Yellow, Color::Black), // yellow text on black background
        // This is where the magic happens:
        // Cast the integer 0xb8000 to a raw mutable pointer to Buffer,
        // then dereference and borrow it as a mutable reference.
        // unsafe is required because we're telling Rust "trust me, this address is valid."
        buffer: unsafe { &mut *(0xb8000 as *mut Buffer) },
    });
}

// ------------------------------------------------------------------
// MACROS — the println! and print! you use everywhere
// ------------------------------------------------------------------

// print! macro — prints without a newline
// ($($arg:tt)*) matches anything you type inside print!(...)
// It passes everything to _print via format_args! which handles formatting
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::vga_buffer::_print(format_args!($($arg)*)));
}

// println! macro — prints with a newline at the end
// Rule 1: println!() with no args → just print a newline
// Rule 2: println!("hello {}", value) → format and print with newline
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;

    // We use interrupts::without_interrupts to avoid deadlocks.
    // If an interrupt occurred while we have the WRITER locked,
    // and the handler also tried to write to the screen, it would hang forever.
    interrupts::without_interrupts(|| {
        WRITER.lock().write_fmt(args).unwrap();
    });
}

// ------------------------------------------------------------------
// TESTS
// ------------------------------------------------------------------

// Basic test — just check that println! doesn't crash
#[test_case]
fn test_println_simple() {
    println!("test_println_simple output");
}

// Stress test — print 200 lines to make sure scrolling works
#[test_case]
fn test_println_many() {
    for _ in 0..200 {
        println!("test_println_many output");
    }
}

// Backspace test — writing a character then backspace should leave the
// cell blank and the cursor back where the character was, and backspacing
// at column 0 should be a harmless no-op rather than underflowing.
#[test_case]
fn test_backspace_erases_last_char() {
    use x86_64::instructions::interrupts;

    interrupts::without_interrupts(|| {
        let mut writer = WRITER.lock();
        writer.new_line(); // start on a fresh, known-blank line
        let start_column = writer.column_position;

        writer.write_byte(b'x');
        writer.write_byte(0x08);

        assert_eq!(writer.column_position, start_column);
        let row = BUFFER_HEIGHT - 1;
        let screen_char = writer.buffer.chars[row][start_column].read();
        assert_eq!(screen_char.ascii_character, b' ');

        // Backspacing again, now at column 0, must not panic or underflow.
        writer.write_byte(0x08);
        assert_eq!(writer.column_position, start_column);
    });
}

// Correctness test — print a string then verify it actually appears in the VGA buffer.
// After println!, the string should be on row BUFFER_HEIGHT - 2
// (because println adds a newline, pushing it one row up from the bottom).
#[test_case]
fn test_println_output() {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;

    let s = "Some test string that fits on a single line";
    interrupts::without_interrupts(|| {
        let mut writer = WRITER.lock();
        writeln!(writer, "\n{}", s).expect("writeln failed");
        for (i, c) in s.chars().enumerate() {
            let screen_char = writer.buffer.chars[BUFFER_HEIGHT - 2][i].read();
            assert_eq!(char::from(screen_char.ascii_character), c);
        }
    });
}
