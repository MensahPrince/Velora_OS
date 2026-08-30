use lazy_static::lazy_static;
use x86_64::VirtAddr;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::structures::gdt::SegmentSelector;



pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            let stack_start = VirtAddr::from_ptr(&raw const STACK);
            let stack_end = stack_start + STACK_SIZE;
            stack_end
        };
        // RSP0: the kernel stack the CPU switches to automatically on any
        // ring3 -> ring0 transition — a syscall (int 0x80), or *any*
        // hardware interrupt (timer, keyboard, ...) that happens to fire
        // while ring 3 code is running. Without this, such a transition
        // would run kernel code on whatever RSP ring 3 happened to leave
        // behind — an untrusted, likely-too-small stack.
        //
        // One shared static stack, same as the double-fault IST stack
        // above: fine as long as only one thread is ever executing in
        // ring 3 at a time (true today — see src/userspace.rs). Running
        // multiple concurrent ring-3 threads would need a per-thread RSP0,
        // swapped in by the scheduler alongside everything else it already
        // switches.
        tss.privilege_stack_table[0] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            let stack_start = VirtAddr::from_ptr(&raw const STACK);
            let stack_end = stack_start + STACK_SIZE;
            stack_end
        };
        tss
    };
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(&TSS));
        let user_code_selector = gdt.add_entry(Descriptor::user_code_segment());
        let user_data_selector = gdt.add_entry(Descriptor::user_data_segment());
        (
            gdt,
            Selectors {
                code_selector,
                tss_selector,
                user_code_selector,
                user_data_selector,
            },
        )
    };
}
struct Selectors {
    code_selector: SegmentSelector,
    tss_selector: SegmentSelector,
    user_code_selector: SegmentSelector,
    user_data_selector: SegmentSelector,
}

pub fn init() {
    use x86_64::instructions::tables::load_tss;
    use x86_64::instructions::segmentation::{CS, Segment};

    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.code_selector);
        load_tss(GDT.1.tss_selector);
    }
}

/// The (code, data) segment selectors for ring 3, for whoever's about to
/// drop into user mode (see `src/userspace.rs`) to load into CS/SS (via
/// the `iretq` frame) and DS/ES/FS/GS respectively.
pub fn user_selectors() -> (SegmentSelector, SegmentSelector) {
    (GDT.1.user_code_selector, GDT.1.user_data_selector)
}
