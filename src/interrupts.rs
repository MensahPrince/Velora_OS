use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

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
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
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

        // The demo syscall gate (src/userspace.rs). DPL 3 so ring-3 code
        // is actually allowed to reach it with `int 0x80` — every other
        // gate above defaults to DPL 0, meaning only the kernel itself
        // could ever trigger them with a software `int`, which is what we
        // want for those.
        idt[SYSCALL_VECTOR as usize]
            .set_handler_fn(syscall_handler)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);

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

// Without this, any page fault (a bad pointer, a missing mapping — exactly
// what per-process page tables will make more common) hits an empty IDT
// slot, double-faults, and reboots with no diagnostic. CR2 holds the
// address that was actually accessed when the fault happened.
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    panic!(
        "EXCEPTION: PAGE FAULT\nAccessed Address: {:?}\nError Code: {:?}\n{:#?}",
        Cr2::read(),
        error_code,
        stack_frame
    );
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!(
        "EXCEPTION: GENERAL PROTECTION FAULT\nError Code: {:#x}\n{:#?}",
        error_code, stack_frame
    );
}

// The demo syscall vector ring-3 code (src/userspace.rs) reaches via
// `int 0x80`. 0x80 sits well clear of both the CPU exception range (0-31)
// and the PIC's hardware IRQ range (32-47), so it can't collide with
// either.
const SYSCALL_VECTOR: u8 = 0x80;

// Doesn't do anything with the caller yet — no register-based argument
// passing, no return value — this only exists to prove the mechanism
// (ring 3 -> int 0x80 -> here -> back to ring 3) actually works. A real
// syscall ABI (reading arguments out of the interrupted registers, not
// just the fixed fields `x86-interrupt` exposes) is follow-up work.
extern "x86-interrupt" fn syscall_handler(_stack_frame: InterruptStackFrame) {
    println!("[kernel] got a syscall from ring 3");
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

// The EOI must happen before scheduler::tick(): tick() may switch to a
// different thread's stack, in which case this specific call doesn't
// "return" here again until that thread is scheduled back in — possibly a
// long time from now. Acknowledging the interrupt has to happen right
// away regardless, or the PIC would never deliver another timer interrupt.
extern "x86-interrupt" fn timer_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
    crate::scheduler::tick();
}

// in/src/interrupts.rs

// Scancode decoding and printing used to happen right here, in interrupt
// context. It now happens in the `print_keypresses` async task
// (src/task/keyboard.rs); this handler just reads the raw scancode and
// hands it off, so keystrokes can't block or slow down other interrupts.
extern "x86-interrupt" fn keyboard_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    use x86_64::instructions::port::Port;
    use x86_64::registers::control::Cr3;

    // add_scancode() (and the task wakeup it can trigger) touches
    // heap-backed queues — but this handler can run with *any* thread's
    // address space active, since a hardware interrupt doesn't care what
    // it interrupted. If that happens to be a thread with its own
    // (isolated) address space, the heap isn't mapped there at all, and
    // touching it faults. Force the kernel's own table for the duration
    // of the heap-touching part, then put back whatever was active before
    // this handler ran — its "resume" (an iretq, possibly straight back
    // into ring 3) needs its own address space, not the kernel's. Plain
    // Cr3::write is fine here (not the atomic asm dance
    // scheduler::context::switch_to needs): RSP never changes in this
    // function, and wherever it currently points — RSP0, or a
    // spawn_isolated thread's own dual-mapped kernel stack — is reachable
    // under both the interrupted address space and the kernel's, by
    // design (see spawn_isolated).
    let (interrupted_page_table, page_table_flags) = Cr3::read();
    let kernel_page_table = crate::scheduler::kernel_page_table();
    if interrupted_page_table != kernel_page_table {
        unsafe { Cr3::write(kernel_page_table, page_table_flags) };
    }

    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    crate::task::keyboard::add_scancode(scancode);

    if interrupted_page_table != kernel_page_table {
        unsafe { Cr3::write(interrupted_page_table, page_table_flags) };
    }

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
