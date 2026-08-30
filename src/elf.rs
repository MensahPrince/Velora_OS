// ============================================================
// elf.rs
// A minimal ELF64 loader: parses just enough of the format (the file
// header and PT_LOAD program headers) to map a static, non-PIE executable
// into a fresh, isolated address space and hand back where to start
// running it.
//
// Deliberately narrow for a first pass: exactly the fields needed to
// support one or more PT_LOAD segments at fixed (non-relocatable, page-
// aligned) addresses. No dynamic linking, no relocations, no section
// headers, and no NX enforcement (this kernel hasn't enabled EFER.NXE, so
// a NO_EXECUTE page-table bit wouldn't mean anything yet even if set) —
// real parsing and real mapping, but the smallest real subset that can
// load something.
// ============================================================

use crate::memory;
use x86_64::{
    VirtAddr,
    structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageTableFlags, PhysFrame, Size4KiB,
    },
};

const EI_MAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 0x3e;
const PT_LOAD: u32 = 1;
const PF_W: u32 = 0x2;

const PAGE_SIZE: u64 = 4096;
/// The loaded binary's user stack: one page, placed a page above the
/// highest PT_LOAD segment so an off-by-one in a segment's own size can't
/// run into it.
const STACK_SIZE: u64 = PAGE_SIZE;

/// Everything needed to actually run a loaded ELF binary.
pub struct LoadedElf {
    /// The L4 frame for this binary's own address space — load into CR3
    /// (via `scheduler::spawn_isolated`) to run it.
    pub page_table: PhysFrame,
    pub entry: VirtAddr,
    pub stack_top: VirtAddr,
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Parse `bytes` as an ELF64 executable, build a fresh address space for
/// it (`memory::new_address_space`), map each PT_LOAD segment and a user
/// stack into it, and return what's needed to actually run it plus the
/// mapper for that new address space — the caller still needs that to
/// call `scheduler::spawn_isolated`, which shares the running thread's own
/// kernel stack into it.
///
/// # Panics
/// On anything that doesn't look like a well-formed ELF64 x86-64
/// executable this loader can actually handle (bad magic, wrong class/
/// endianness/machine/type, a segment vaddr that isn't page-aligned). A
/// real loader would reject a bad binary and let its caller decide what
/// to do; panicking is an accepted simplification while the only ELF this
/// kernel ever loads is the one it built itself (see
/// `userspace::build_test_elf`).
pub fn load(
    bytes: &[u8],
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> (OffsetPageTable<'static>, LoadedElf) {
    assert!(bytes.len() >= 64, "ELF file too short to hold a header");
    assert_eq!(&bytes[0..4], &EI_MAG, "not an ELF file (bad magic)");
    assert_eq!(bytes[4], ELFCLASS64, "only 64-bit ELF is supported");
    assert_eq!(bytes[5], ELFDATA2LSB, "only little-endian ELF is supported");
    assert_eq!(
        read_u16(bytes, 16),
        ET_EXEC,
        "only static ET_EXEC binaries are supported (no PIE, no dynamic linking)"
    );
    assert_eq!(read_u16(bytes, 18), EM_X86_64, "not an x86-64 ELF file");

    let entry = read_u64(bytes, 24);
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;

    let (l4_frame, mut mapper) =
        unsafe { memory::new_address_space(physical_memory_offset, frame_allocator) };

    let mut highest_mapped = 0u64;

    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if read_u32(bytes, ph) != PT_LOAD {
            continue;
        }
        let p_flags = read_u32(bytes, ph + 4);
        let p_offset = read_u64(bytes, ph + 8) as usize;
        let p_vaddr = read_u64(bytes, ph + 16);
        let p_filesz = read_u64(bytes, ph + 32) as usize;
        let p_memsz = read_u64(bytes, ph + 40);

        let writable = p_flags & PF_W != 0;
        let file_bytes = &bytes[p_offset..p_offset + p_filesz];
        map_segment(
            &mut mapper,
            physical_memory_offset,
            frame_allocator,
            file_bytes,
            p_vaddr,
            p_memsz,
            writable,
        );

        highest_mapped = highest_mapped.max(p_vaddr + p_memsz);
    }

    let stack_bottom = align_up(highest_mapped, PAGE_SIZE) + PAGE_SIZE;
    map_segment(
        &mut mapper,
        physical_memory_offset,
        frame_allocator,
        &[],
        stack_bottom,
        STACK_SIZE,
        true,
    );
    // 16-aligned, matching the same SysV requirement userspace.rs's hand
    // demos already have to satisfy.
    let stack_top = VirtAddr::new(stack_bottom + STACK_SIZE - 16);

    (
        mapper,
        LoadedElf {
            page_table: l4_frame,
            entry: VirtAddr::new(entry),
            stack_top,
        },
    )
}

fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

/// Map `mem_size` bytes (rounded up to whole pages) at `vaddr`, copying
/// `file_bytes` in at the start and zero-filling the rest — the standard
/// ELF PT_LOAD behavior, where `p_memsz >= p_filesz` and the difference
/// (typically a segment's BSS) is expected to read as zero. Also used
/// (with `file_bytes` empty) to map the plain, zeroed stack page.
fn map_segment(
    mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    file_bytes: &[u8],
    vaddr: u64,
    mem_size: u64,
    writable: bool,
) {
    if mem_size == 0 {
        return;
    }
    assert_eq!(
        vaddr % PAGE_SIZE,
        0,
        "this minimal loader requires page-aligned segment addresses"
    );
    // Below the canonical-address boundary (bit 47 clear): this loader's
    // own address-space bookkeeping (in `load`, above) does its
    // highest-address/alignment arithmetic on raw u64s and only calls
    // `VirtAddr::new` (which sign-extends bit 47 into bits 48-63) at the
    // point each segment actually gets mapped — a load address placed
    // right at or above that boundary was found (empirically, in
    // development) to end up executing at CPL 3 with a GPF rather than
    // running, for reasons not fully traced to a single line. Rather than
    // ship that footgun, this loader simply doesn't support it yet: keep
    // load addresses comfortably below 0x0000_8000_0000_0000.
    assert!(
        vaddr < 0x0000_8000_0000_0000,
        "this minimal loader doesn't support segment addresses at or above the canonical boundary (2^47)"
    );

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }

    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(vaddr));
    let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(vaddr + mem_size - 1));
    let page_count = end_page - start_page + 1;

    for i in 0..page_count {
        let page = start_page + i;
        let frame = frame_allocator
            .allocate_frame()
            .expect("no physical frames left to load ELF segment");
        unsafe {
            mapper
                .map_to(page, frame, flags, frame_allocator)
                .expect("failed to map ELF segment page")
                .flush();
        }

        // Populated through the physical-offset alias, not through
        // `page`'s own address: this table isn't the active one yet (see
        // userspace.rs's map_shellcode_page for the same reasoning).
        let dst = (physical_memory_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
        unsafe { core::ptr::write_bytes(dst, 0, PAGE_SIZE as usize) };

        let page_offset_in_segment = (i * PAGE_SIZE) as usize;
        if page_offset_in_segment < file_bytes.len() {
            let copy_len = (file_bytes.len() - page_offset_in_segment).min(PAGE_SIZE as usize);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    file_bytes.as_ptr().add(page_offset_in_segment),
                    dst,
                    copy_len,
                );
            }
        }
    }
}
