use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use crate::println;
use lazy_static::lazy_static;

// in src/interrupts.rs

use crate::gdt;

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            idt.double_fault.set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX); 
        }
        idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard.as_usize()].set_handler_fn(keyboard_interrupt_handler);

        // Every other PIC line (spurious IRQ7/IRQ15, RTC, a second serial
        // port, ...) is left unmasked by PICS.initialize(). Without a
        // handler here, one of those firing would hit an empty IDT slot and
        // triple-fault the kernel. Give them all a minimal handler that just
        // acknowledges the interrupt.
        idt[(PIC_1_OFFSET + 2) as usize].set_handler_fn(irq2_handler);
        idt[(PIC_1_OFFSET + 3) as usize].set_handler_fn(irq3_handler);
        idt[(PIC_1_OFFSET + 4) as usize].set_handler_fn(irq4_handler);
        idt[(PIC_1_OFFSET + 5) as usize].set_handler_fn(irq5_handler);
        idt[(PIC_1_OFFSET + 6) as usize].set_handler_fn(irq6_handler);
        idt[(PIC_1_OFFSET + 7) as usize].set_handler_fn(irq7_handler);
        idt[PIC_2_OFFSET as usize].set_handler_fn(irq8_handler);
        idt[(PIC_2_OFFSET + 1) as usize].set_handler_fn(irq9_handler);
        idt[(PIC_2_OFFSET + 2) as usize].set_handler_fn(irq10_handler);
        idt[(PIC_2_OFFSET + 3) as usize].set_handler_fn(irq11_handler);
        idt[(PIC_2_OFFSET + 4) as usize].set_handler_fn(irq12_handler);
        idt[(PIC_2_OFFSET + 5) as usize].set_handler_fn(irq13_handler);
        idt[(PIC_2_OFFSET + 6) as usize].set_handler_fn(irq14_handler);
        idt[(PIC_2_OFFSET + 7) as usize].set_handler_fn(irq15_handler);

        idt
    };
}


pub fn init_idt() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

// IPC Interrupts


use pic8259::ChainedPics;
use spin;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });


#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

macro_rules! unhandled_pic_interrupt {
    ($name:ident, $vector:expr) => {
        extern "x86-interrupt" fn $name(_stack_frame: InterruptStackFrame) {
            unsafe {
                PICS.lock().notify_end_of_interrupt($vector);
            }
        }
    };
}

unhandled_pic_interrupt!(irq2_handler, PIC_1_OFFSET + 2);
unhandled_pic_interrupt!(irq3_handler, PIC_1_OFFSET + 3);
unhandled_pic_interrupt!(irq4_handler, PIC_1_OFFSET + 4);
unhandled_pic_interrupt!(irq5_handler, PIC_1_OFFSET + 5);
unhandled_pic_interrupt!(irq6_handler, PIC_1_OFFSET + 6);
unhandled_pic_interrupt!(irq7_handler, PIC_1_OFFSET + 7);
unhandled_pic_interrupt!(irq8_handler, PIC_2_OFFSET);
unhandled_pic_interrupt!(irq9_handler, PIC_2_OFFSET + 1);
unhandled_pic_interrupt!(irq10_handler, PIC_2_OFFSET + 2);
unhandled_pic_interrupt!(irq11_handler, PIC_2_OFFSET + 3);
unhandled_pic_interrupt!(irq12_handler, PIC_2_OFFSET + 4);
unhandled_pic_interrupt!(irq13_handler, PIC_2_OFFSET + 5);
unhandled_pic_interrupt!(irq14_handler, PIC_2_OFFSET + 6);
unhandled_pic_interrupt!(irq15_handler, PIC_2_OFFSET + 7);

use crate::print;

extern "x86-interrupt" fn timer_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

// in/src/interrupts.rs

extern "x86-interrupt" fn keyboard_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
    use spin::Mutex;
    use x86_64::instructions::port::Port;

    lazy_static! {
        static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(Keyboard::new(ScancodeSet1::new(),
                layouts::Us104Key, HandleControl::Ignore)
            );
    }

    let mut keyboard = KEYBOARD.lock();
    let mut port = Port::new(0x60);

    let scancode: u8 = unsafe { port.read() };
    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                DecodedKey::Unicode(character) => print!("{}", character),
                DecodedKey::RawKey(key) => print!("{:?}", key),
            }
        }
    }

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
