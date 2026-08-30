use lazy_static::lazy_static;
use x86_64::VirtAddr;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::structures::gdt::SegmentSelector;



pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

// RSP0 — the kernel stack the CPU switches to automatically on any
// ring3 -> ring0 transition (a syscall, or *any* hardware interrupt that
// happens to fire while ring-3 code is running) — used to be a single
// shared static here, which only worked with one ring-3 thread at a time:
// two threads transitioning through the same physical stack region can
// corrupt each other's in-flight state. It's now per-thread instead (see
// `set_rsp0` and `scheduler::schedule`, which calls it on every switch),
// which means `TSS` has to be genuinely mutable at runtime rather than a
// `lazy_static!` — that only ever hands out `&TaskStateSegment`, by
// design, since it's meant for one-time initialization. A plain
// `static mut`, written through raw pointers (`&raw mut`/`&raw const`,
// never a live `&mut` or `&` reference held across other code), is the
// standard way to have real mutable global state in a `no_std` kernel.
static mut TSS: TaskStateSegment = TaskStateSegment::new();

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
        // SAFETY: only the *address* of TSS is needed here (to bake into
        // the descriptor) — its fields don't need to be populated yet,
        // and this shared reference doesn't outlive this statement.
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(unsafe {
            &*core::ptr::addr_of!(TSS)
        }));
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

    unsafe {
        let tss = &mut *core::ptr::addr_of_mut!(TSS);
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            let stack_start = VirtAddr::from_ptr(&raw const STACK);
            let stack_end = stack_start + STACK_SIZE;
            stack_end
        };
        // A default RSP0, for any thread that hasn't been assigned its
        // own yet (in practice, just thread 0 — see `scheduler::init` —
        // which is never actually expected to enter ring 3). Every other
        // thread gets its own via `set_rsp0`, called on every scheduler
        // switch (`scheduler::schedule`).
        tss.privilege_stack_table[0] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            let stack_start = VirtAddr::from_ptr(&raw const STACK);
            let stack_end = stack_start + STACK_SIZE;
            stack_end
        };
    }

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

/// Point RSP0 at `stack_top` — called by `scheduler::schedule` on every
/// switch, so whichever thread is about to run has its *own* privilege-
/// transition stack rather than sharing one with every other ring-3-
/// capable thread in the system.
///
/// Safe to call as a plain write, unlike the CR3 switch
/// `scheduler::context::switch_to` performs: this doesn't change what
/// memory is currently accessible (RSP0 is only consulted by the CPU
/// later, at the next actual interrupt/syscall), so there's no
/// "in-between" state to worry about, and no reason it needs to happen
/// atomically with the register/stack switch the way CR3 does.
///
/// # Safety
/// Must not be called concurrently from two contexts — true today, since
/// this kernel is single-core and every call site already runs with
/// interrupts disabled.
pub unsafe fn set_rsp0(stack_top: VirtAddr) {
    unsafe {
        (*core::ptr::addr_of_mut!(TSS)).privilege_stack_table[0] = stack_top;
    }
}
