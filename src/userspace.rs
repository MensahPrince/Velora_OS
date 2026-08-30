// ============================================================
// userspace.rs
// Two demos, in increasing order of how real they are:
//
// - `run_demo`: proves ring 3 (user-mode) execution works at all — a
//   hand-written shellcode page invoked via IRETQ, calling back into the
//   kernel through a software interrupt (int 0x80, src/syscall.rs). Still
//   shares the kernel's own page tables, just at a lower privilege level
//   (CPL 3 instead of CPL 0) — no actual isolation.
// - `run_isolated_demo`: the same shellcode, but running in its own
//   address space (see `memory::new_address_space`), switched to via CR3
//   whenever its thread runs (`scheduler::spawn_isolated`). This is what
//   real process isolation actually rests on: the kernel's own view of
//   memory (see `prove_isolation` in main.rs) can't see this page at all,
//   even though the isolated thread runs from it just fine.
//
// Both demos run the same shellcode: read one byte via sys_read, write it
// straight back via sys_write, forever — a genuine (if minimal) read/write
// loop through the real syscall ABI, not just a fixed debug print.
// ============================================================

use crate::{elf, gdt, memory, scheduler, syscall};
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{
    VirtAddr,
    instructions::segmentation::{DS, ES, FS, GS, Segment},
    structures::paging::{FrameAllocator, Mapper, OffsetPageTable, Page, PageTableFlags, Size4KiB},
};

/// Where the demo's code+stack page lives. Arbitrary but deliberately far
/// from every other mapping this kernel makes (the heap at
/// 0x4444_4444_0000, the earlier paging demo at 0xdeadbeaf000): that keeps
/// its whole page-table chain (P4 down to P1) unmapped beforehand, so
/// `map_to` below creates every level fresh and propagates
/// `USER_ACCESSIBLE` all the way down. Reusing an address whose upper
/// levels already exist from an earlier, kernel-only mapping would need
/// those levels re-flagged too — `map_to` only sets flags on levels it
/// creates, not ones it finds already there.
const USER_PAGE_ADDR: u64 = 0x5555_5555_0000;

/// Where the *isolated* demo's page lives — in its own address space, so
/// reusing `USER_PAGE_ADDR` would have been just as safe, but a distinct
/// address (in a P4 slot nothing else in this kernel ever uses) keeps the
/// two demos easy to tell apart in diagnostics like `prove_isolation`.
pub const ISOLATED_USER_PAGE_ADDR: u64 = 0x6000_0000_0000;

/// Assembles the demo's machine code by hand — there's no reliable way to
/// know how many bytes a compiled Rust function occupies in order to copy
/// "just it" into the user page, so raw opcodes are written out directly
/// instead. Builds:
///
/// ```text
/// read_loop:
///     mov rax, SYS_READ
///     mov rdi, 0            ; fd = stdin
///     mov rsi, buf_addr
///     mov rdx, 1            ; up to 1 byte
///     int 0x80              ; rax = bytes actually read (0 or 1)
///     test rax, rax
///     jz read_loop          ; sys_read never blocks — poll until we get one
///     mov rax, SYS_WRITE
///     mov rdi, 1            ; fd = stdout
///     mov rsi, buf_addr
///     mov rdx, 1
///     int 0x80              ; echo the byte straight back
///     jmp read_loop
/// buf: <1 byte scratch space>
/// ```
///
/// `buf_addr` (`page_addr + code.len()`) and both jump displacements are
/// computed from the actual encoded lengths, not hand-counted — the two
/// `mov_imm64` calls that reference `buf_addr` are written with a
/// placeholder first and patched once the real address is known, and each
/// jump's rel8 is computed from where its own next instruction actually
/// ends up. That trades a well-contained "patch it up afterward" step for
/// never having to get a manual byte-offset count right by hand, which is
/// exactly the kind of arithmetic that's easy to get subtly wrong and hard
/// to debug once it's wrong — a bad jump target here would land execution
/// on an arbitrary instruction boundary (or none), with no guarantee of
/// hitting a byte sequence that even decodes as valid x86-64.
fn build_echo_shellcode(page_addr: u64) -> Vec<u8> {
    fn mov_imm64(code: &mut Vec<u8>, reg_opcode: u8, value: u64) {
        code.push(0x48); // REX.W
        code.push(0xB8 + reg_opcode);
        code.extend_from_slice(&value.to_le_bytes());
    }
    // B8+r register encoding.
    const RAX: u8 = 0;
    const RDX: u8 = 2;
    const RSI: u8 = 6;
    const RDI: u8 = 7;

    let mut code = Vec::new();
    let read_loop = code.len();

    mov_imm64(&mut code, RAX, syscall::SYS_READ);
    mov_imm64(&mut code, RDI, 0); // fd = stdin
    let read_buf_patch_at = code.len() + 2; // +2 skips the REX+opcode bytes mov_imm64 is about to push
    mov_imm64(&mut code, RSI, 0); // buf_addr, patched in below
    mov_imm64(&mut code, RDX, 1); // len = 1
    code.extend_from_slice(&[0xcd, 0x80]); // int 0x80
    code.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax, rax
    let jz_opcode_at = code.len();
    code.extend_from_slice(&[0x74, 0x00]); // jz read_loop (patched below)
    code[jz_opcode_at + 1] = rel8(read_loop, code.len());

    mov_imm64(&mut code, RAX, syscall::SYS_WRITE);
    mov_imm64(&mut code, RDI, 1); // fd = stdout
    let write_buf_patch_at = code.len() + 2;
    mov_imm64(&mut code, RSI, 0); // buf_addr, patched in below
    mov_imm64(&mut code, RDX, 1); // len = 1
    code.extend_from_slice(&[0xcd, 0x80]); // int 0x80
    let jmp_opcode_at = code.len();
    code.extend_from_slice(&[0xeb, 0x00]); // jmp read_loop (patched below)
    code[jmp_opcode_at + 1] = rel8(read_loop, code.len());

    // The scratch buffer immediately follows the code — now that the code
    // is fully assembled, its real address is known.
    let buf_addr = page_addr + code.len() as u64;
    code[read_buf_patch_at..read_buf_patch_at + 8].copy_from_slice(&buf_addr.to_le_bytes());
    code[write_buf_patch_at..write_buf_patch_at + 8].copy_from_slice(&buf_addr.to_le_bytes());
    code.push(0); // the buffer byte itself

    code
}

/// `rel8` for a short jump: `target - next_instruction`, where
/// `next_instruction_offset` is where the *following* instruction starts
/// (i.e. right after the jump's own 2 bytes) — panics rather than silently
/// truncate if the jump would need to travel further than a single byte
/// can encode, which nothing in this small, fixed shellcode should ever
/// do.
fn rel8(target_offset: usize, next_instruction_offset: usize) -> u8 {
    let delta = target_offset as i64 - next_instruction_offset as i64;
    i8::try_from(delta).expect("shellcode jump target out of rel8 range") as u8
}

/// Map a demo code+stack page at `addr` in `mapper` and copy the shellcode
/// into it. The code lives at the start of the page; the stack (unused by
/// this shellcode — it never pushes anything) grows down from the page's
/// end, sharing the same page since this demo is small enough that the two
/// can't realistically collide.
///
/// The shellcode is written through `physical_memory_offset + frame`, not
/// through `addr` itself: `addr` is only guaranteed to be mapped once
/// `mapper`'s own table is the *active* one, which for an isolated address
/// space (`spawn_isolated_demo`) isn't true yet at this point — the whole
/// point of `OffsetPageTable`-based setup is that every table this kernel
/// builds shares the same offset window, so a frame belonging to it is
/// still reachable through that alias regardless of whether its table is
/// loaded into CR3 yet.
fn map_shellcode_page(
    mapper: &mut OffsetPageTable<'_>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    physical_memory_offset: VirtAddr,
    addr: u64,
) {
    let page = Page::containing_address(VirtAddr::new(addr));
    let frame = frame_allocator
        .allocate_frame()
        .expect("no physical frames left for the ring 3 demo page");
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    unsafe {
        mapper
            .map_to(page, frame, flags, frame_allocator)
            .expect("failed to map the ring 3 demo page")
            .flush();
    }

    let shellcode = build_echo_shellcode(addr);
    let code_ptr = (physical_memory_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
    unsafe {
        core::ptr::copy_nonoverlapping(shellcode.as_ptr(), code_ptr, shellcode.len());
    }
}

/// Map the demo's code+stack page and copy the shellcode into it, in the
/// kernel's own (shared) address space. Call once, from kernel_main (which
/// already has a mapper and frame allocator on hand), before spawning
/// `run_demo` as a scheduler thread.
pub fn map_demo_page(
    mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    map_shellcode_page(mapper, frame_allocator, physical_memory_offset, USER_PAGE_ADDR);
}

/// Build a fresh, isolated address space and map the (identical) demo
/// shellcode into it at `ISOLATED_USER_PAGE_ADDR` — that address space is
/// what `main.rs` checks its own page tables against to prove isolation,
/// so this part always happens. Actually *running* it (`run: true`) spawns
/// a thread that drops into it, which starts echoing typed characters
/// straight back via its own sys_read/sys_write calls — a good one-time
/// proof the syscall ABI works end to end, but if left on permanently
/// every keystroke shows up twice (once from the kernel's own keyboard
/// task, once from this), which reads as a bug rather than a feature.
/// `kernel_mapper` is the caller's own (shared) mapper, needed so the new
/// thread's kernel-mode stack can be shared into the isolated table too
/// (see `scheduler::spawn_isolated`).
pub fn spawn_isolated_demo(
    kernel_mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    run: bool,
) {
    let (l4_frame, mut isolated_mapper) =
        unsafe { memory::new_address_space(physical_memory_offset, frame_allocator) };

    map_shellcode_page(
        &mut isolated_mapper,
        frame_allocator,
        physical_memory_offset,
        ISOLATED_USER_PAGE_ADDR,
    );

    if run {
        scheduler::spawn_isolated(
            run_isolated_demo,
            l4_frame,
            kernel_mapper,
            &mut isolated_mapper,
            frame_allocator,
        );
    }
}

/// Spawned as a scheduler thread (`scheduler::spawn(run_demo)`). Drops to
/// ring 3 and runs the read/write echo loop `map_demo_page` placed there
/// — so, like `thread_trampoline`, this function's own body never really
/// executes past the call that takes us there.
pub fn run_demo() -> ! {
    let entry = VirtAddr::new(USER_PAGE_ADDR);
    let stack_top = VirtAddr::new(USER_PAGE_ADDR + 4096 - 16); // top of the same page, 16-aligned

    unsafe {
        enter_ring3(entry, stack_top);
    }
}

/// Spawned via `spawn_isolated_demo`, which sets up this thread's own
/// address space before it ever runs. Otherwise identical to `run_demo` —
/// it's the address space it runs under (not this function) that makes it
/// isolated.
pub fn run_isolated_demo() -> ! {
    let entry = VirtAddr::new(ISOLATED_USER_PAGE_ADDR);
    let stack_top = VirtAddr::new(ISOLATED_USER_PAGE_ADDR + 4096 - 16);

    unsafe {
        enter_ring3(entry, stack_top);
    }
}

/// Where the ELF demo's program gets loaded — another P4 slot nothing
/// else in this kernel uses. Matters less for collision-avoidance than it
/// once did (every demo here gets its own address space now), but keeps
/// things easy to tell apart in diagnostics.
const ELF_LOAD_ADDR: u64 = 0x7000_0000_0000;

/// Filled in by whichever of `spawn_elf_demo` / `spawn_disk_elf_demo` last
/// ran, before the thread it spawns ever runs. `run_elf_demo` is a plain
/// fn pointer (`scheduler::spawn_isolated` can't carry captured state, the
/// same constraint `run_demo`/`run_isolated_demo` work around by
/// hardcoding a known constant address) but neither the entry point nor
/// the stack's placement is fixed at compile time here the way it is for
/// those two demos: `spawn_disk_elf_demo` loads whatever ELF `fs::read_file`
/// happened to hand it, at whatever address *that* binary's own linker
/// chose — so both are read back from here instead of being hardcoded or
/// re-derived.
static ELF_DEMO_ENTRY: AtomicU64 = AtomicU64::new(0);
static ELF_DEMO_STACK_TOP: AtomicU64 = AtomicU64::new(0);

/// Wraps the same read/write echo machine code `build_echo_shellcode`
/// already builds in a minimal, valid ELF64 executable — real headers,
/// loaded through the real (if narrow) parser in src/elf.rs, rather than
/// mapped directly the way `run_demo`/`run_isolated_demo` are.
fn build_test_elf(load_addr: u64) -> Vec<u8> {
    let payload = build_echo_shellcode(load_addr);

    const EHDR_SIZE: u64 = 64;
    const PHDR_SIZE: u64 = 56;
    let payload_offset = EHDR_SIZE + PHDR_SIZE;

    let mut elf = Vec::with_capacity((payload_offset + payload.len() as u64) as usize);

    // -- ELF header --
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident[0..4]: magic
    elf.push(2); // EI_CLASS = ELFCLASS64
    elf.push(1); // EI_DATA = ELFDATA2LSB
    elf.push(1); // EI_VERSION = EV_CURRENT
    elf.push(0); // EI_OSABI = ELFOSABI_SYSV
    elf.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + padding = e_ident[9..16]
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    elf.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine = EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&load_addr.to_le_bytes()); // e_entry
    elf.extend_from_slice(&EHDR_SIZE.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (no section headers)
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(elf.len() as u64, EHDR_SIZE);

    // -- program header: one PT_LOAD segment, R+W+X (the payload is both
    // code and its own read/write scratch buffer, same as the other
    // demos' single combined page) --
    elf.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    elf.extend_from_slice(&7u32.to_le_bytes()); // p_flags = PF_X|PF_W|PF_R
    elf.extend_from_slice(&payload_offset.to_le_bytes()); // p_offset
    elf.extend_from_slice(&load_addr.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&load_addr.to_le_bytes()); // p_paddr (unused by our loader)
    elf.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // p_filesz
    elf.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // p_memsz
    elf.extend_from_slice(&4096u64.to_le_bytes()); // p_align
    assert_eq!(elf.len() as u64, payload_offset);

    elf.extend_from_slice(&payload);
    elf
}

/// Builds `build_test_elf`, loads it through the real ELF loader
/// (src/elf.rs) into its own address space, and — if `run` — spawns a
/// thread that runs it: the same read/write echo behavior as
/// `run_isolated_demo`, but arrived at by parsing an actual (if hand-
/// built) ELF file instead of hand-mapping a page directly. The binary is
/// always built and loaded regardless of `run` (so the loader is always
/// really exercised), just not necessarily executed — same reasoning as
/// `spawn_isolated_demo`'s own `run` parameter.
pub fn spawn_elf_demo(
    kernel_mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    run: bool,
) {
    let elf_bytes = build_test_elf(ELF_LOAD_ADDR);
    spawn_loaded_elf_demo(&elf_bytes, kernel_mapper, physical_memory_offset, frame_allocator, run);
}

/// Same as `spawn_elf_demo`, but for an ELF binary read from a real
/// filesystem (src/fs.rs) instead of built in memory — see
/// `disk/echo.s` and `build.rs` for where `bytes` actually comes from.
/// Kept separate from `spawn_elf_demo` (rather than one function taking
/// an enum) because the two callers, in main.rs, genuinely differ in what
/// they have on hand before calling: one already has `elf_bytes` sitting
/// in memory from `fs::read_file`, the other builds them fresh each time.
pub fn spawn_disk_elf_demo(
    elf_bytes: &[u8],
    kernel_mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    run: bool,
) {
    spawn_loaded_elf_demo(elf_bytes, kernel_mapper, physical_memory_offset, frame_allocator, run);
}

fn spawn_loaded_elf_demo(
    elf_bytes: &[u8],
    kernel_mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    run: bool,
) {
    let (mut isolated_mapper, loaded) =
        elf::load(elf_bytes, physical_memory_offset, frame_allocator);

    crate::println!(
        "loaded a real ELF binary: entry={:?} stack_top={:?}",
        loaded.entry,
        loaded.stack_top
    );
    ELF_DEMO_ENTRY.store(loaded.entry.as_u64(), Ordering::Relaxed);
    ELF_DEMO_STACK_TOP.store(loaded.stack_top.as_u64(), Ordering::Relaxed);

    if run {
        scheduler::spawn_isolated(
            run_elf_demo,
            loaded.page_table,
            kernel_mapper,
            &mut isolated_mapper,
            frame_allocator,
        );
    }
}

/// Spawned via `spawn_elf_demo` or `spawn_disk_elf_demo`. Both the entry
/// point and the stack address are read back from the statics those
/// functions filled in, rather than hardcoded — needed now that this
/// trampoline serves two demos whose ELFs are linked at entirely
/// different addresses (`ELF_LOAD_ADDR` for the in-memory one; whatever
/// `disk/link.ld` chose for the on-disk one).
pub fn run_elf_demo() -> ! {
    let entry = VirtAddr::new(ELF_DEMO_ENTRY.load(Ordering::Relaxed));
    let stack_top = VirtAddr::new(ELF_DEMO_STACK_TOP.load(Ordering::Relaxed));

    unsafe {
        enter_ring3(entry, stack_top);
    }
}

/// Drop from ring 0 to ring 3 by hand-building the frame `iretq` expects
/// (SS, RSP, RFLAGS, CS, RIP, pushed in that order) and executing it.
/// `iretq` doesn't "return" here in the normal sense — from this point on
/// the CPU is running at CPL 3, executing whatever's at `entry`.
///
/// # Safety
/// `entry` and `stack_top` must point into a page mapped PRESENT |
/// USER_ACCESSIBLE (and, since it also serves as the stack, WRITABLE) —
/// see `map_demo_page`.
unsafe fn enter_ring3(entry: VirtAddr, stack_top: VirtAddr) -> ! {
    let (code_selector, data_selector) = gdt::user_selectors();

    unsafe {
        // CS and SS get set by `iretq` itself, from the frame pushed
        // below — but DS/ES/FS/GS aren't touched by iretq, so they'd
        // otherwise keep holding kernel (DPL 0) selectors, which ring 3
        // code isn't allowed to use. Loading them here, while still at
        // CPL 0, is valid (a CPL-0 load of an RPL-3 selector into a data
        // segment register is permitted) and is the standard fix.
        DS::set_reg(data_selector);
        ES::set_reg(data_selector);
        FS::set_reg(data_selector);
        GS::set_reg(data_selector);

        asm!(
            "push {ss}",
            "push {stack}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) u64::from(data_selector.0),
            stack = in(reg) stack_top.as_u64(),
            rflags = in(reg) 0x202u64, // IF (bit 9) set; bit 1 is reserved-as-1
            cs = in(reg) u64::from(code_selector.0),
            rip = in(reg) entry.as_u64(),
            options(noreturn),
        );
    }
}
