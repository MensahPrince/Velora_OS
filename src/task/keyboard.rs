// ============================================================
// task/keyboard.rs
// Async keyboard input.
//
// The keyboard interrupt handler (src/interrupts.rs) used to decode the
// scancode and call `print!` right there in interrupt context — meaning
// every keystroke did keyboard-layout decoding and a VGA write with
// interrupts disabled. Here the ISR only pushes the raw scancode onto a
// lock-free queue and wakes whoever is waiting; decoding and printing move
// into `print_keypresses`, an ordinary async task the executor polls like
// any other.
// ============================================================

use crate::print;
use conquer_once::spin::OnceCell;
use core::{
    pin::Pin,
    task::{Context, Poll},
};
use crossbeam_queue::ArrayQueue;
use futures_util::{
    stream::{Stream, StreamExt},
    task::AtomicWaker,
};
use pc_keyboard::{DecodedKey, HandleControl, Keyboard, ScancodeSet1, layouts};

/// Scancodes queued up by the interrupt handler, waiting to be decoded by
/// `print_keypresses`. Bounded so a burst of keystrokes can't grow memory
/// use without limit; if it fills up, further keystrokes are dropped rather
/// than blocking the interrupt handler.
static SCANCODE_QUEUE: OnceCell<ArrayQueue<u8>> = OnceCell::uninit();
static WAKER: AtomicWaker = AtomicWaker::new();

/// Called by the keyboard interrupt handler with the raw scancode byte read
/// from port 0x60. Must never block, allocate on the heap, or panic — it
/// runs with interrupts disabled inside the ISR.
pub(crate) fn add_scancode(scancode: u8) {
    if let Ok(queue) = SCANCODE_QUEUE.try_get() {
        if queue.push(scancode).is_err() {
            crate::println!("WARNING: scancode queue full; dropping keyboard input");
        } else {
            WAKER.wake();
        }
    } else {
        crate::println!("WARNING: scancode queue uninitialized");
    }
}

/// Create the scancode queue. Must be called once, before interrupts are
/// enabled (i.e. before `velora_os::init()`), so the keyboard ISR never
/// fires against an uninitialized queue and silently drops a keystroke.
pub fn init_queue() {
    SCANCODE_QUEUE
        .try_init_once(|| ArrayQueue::new(100))
        .expect("keyboard::init_queue should only be called once");
}

pub struct ScancodeStream {
    _private: (),
}

impl ScancodeStream {
    pub fn new() -> Self {
        debug_assert!(
            SCANCODE_QUEUE.is_initialized(),
            "keyboard::init_queue() must be called before ScancodeStream::new()"
        );
        ScancodeStream { _private: () }
    }
}

impl Stream for ScancodeStream {
    type Item = u8;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<u8>> {
        let queue = SCANCODE_QUEUE
            .try_get()
            .expect("scancode queue not initialized");

        // Fast path: a scancode is already waiting, no need to register a
        // waker at all.
        if let Some(scancode) = queue.pop() {
            return Poll::Ready(Some(scancode));
        }

        WAKER.register(cx.waker());
        match queue.pop() {
            Some(scancode) => {
                WAKER.take();
                Poll::Ready(Some(scancode))
            }
            None => Poll::Pending,
        }
    }
}

/// Decodes queued scancodes into key events and prints resolved characters,
/// forever. Spawn this once as a `Task` in the executor.
pub async fn print_keypresses() {
    let mut scancodes = ScancodeStream::new();
    let mut keyboard = Keyboard::new(ScancodeSet1::new(), layouts::Us104Key, HandleControl::Ignore);

    while let Some(scancode) = scancodes.next().await {
        if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
            if let Some(key) = keyboard.process_keyevent(key_event) {
                match key {
                    DecodedKey::Unicode(character) => print!("{}", character),
                    DecodedKey::RawKey(key) => print!("{:?}", key),
                }
            }
        }
    }
}
