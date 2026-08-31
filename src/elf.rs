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
        FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageTableFlags, PhysFrame,
        Size4KiB,
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

/// Read a little-endian integer at `base + offset` — `None` if that range
/// falls outside `bytes` at all, computed via `checked_add` rather than
/// plain `+` so a `base`/`offset` combination near `usize::MAX` (fully
/// attacker-controlled: `base` is usually a program-header offset read
/// straight out of the file) fails cleanly instead of overflowing.
fn read_u16(bytes: &[u8], base: usize, offset: usize) -> Option<u16> {
    let start = base.checked_add(offset)?;
    let end = start.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(start..end)?.try_into().ok()?))
}
fn read_u32(bytes: &[u8], base: usize, offset: usize) -> Option<u32> {
    let start = base.checked_add(offset)?;
    let end = start.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(start..end)?.try_into().ok()?))
}
fn read_u64(bytes: &[u8], base: usize, offset: usize) -> Option<u64> {
    let start = base.checked_add(offset)?;
    let end = start.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(start..end)?.try_into().ok()?))
}

/// Parse `bytes` as an ELF64 executable, build a fresh address space for
/// it (`memory::new_address_space`), map each PT_LOAD segment and a user
/// stack into it, and return what's needed to actually run it plus the
/// mapper for that new address space — the caller still needs that to
/// call `scheduler::spawn_isolated`/`spawn_user`, which shares the running
/// thread's own kernel stack into it.
///
/// Returns `None` — never panics — on anything that doesn't look like a
/// well-formed ELF64 x86-64 executable this loader can actually handle
/// (too short, bad magic, wrong class/endianness/machine/type, a
/// truncated or out-of-range program header table, a segment vaddr that
/// isn't page-aligned or overflows the address space, ...). This used to
/// be a set of `assert!`s — an accepted shortcut while the only ELF this
/// kernel ever loaded was one it built itself (`userspace::build_test_elf`)
/// or `disk/echo.s`, both trusted by construction. `syscall::sys_spawn`
/// changed that: it can hand this an arbitrary file a ring-3 program named
/// by path, and a malformed one panicking the entire kernel over one
/// process's bad choice of file is exactly the class of bug this kernel
/// spent real effort closing elsewhere (see `fs::read_file`,
/// `syscall::copy_from_user`) — this loader needed the same treatment.
///
/// On failure, whatever `memory::new_address_space` (and any segment
/// already mapped before the failure) allocated is freed back
/// (`memory::free_address_space`) rather than leaked — this address space
/// never got far enough to have anything shared into it the way
/// `scheduler::spawn_user` eventually would, so there's nothing to
/// preserve.
pub fn load(
    bytes: &[u8],
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut (impl FrameAllocator<Size4KiB> + FrameDeallocator<Size4KiB>),
) -> Option<(OffsetPageTable<'static>, LoadedElf)> {
    if bytes.len() < 64 {
        return None;
    }
    if bytes[0..4] != EI_MAG || bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB {
        return None;
    }
    if read_u16(bytes, 0, 16)? != ET_EXEC || read_u16(bytes, 0, 18)? != EM_X86_64 {
        return None;
    }

    let (l4_frame, mut mapper) =
        unsafe { memory::new_address_space(physical_memory_offset, frame_allocator) };

    match load_segments_and_stack(bytes, &mut mapper, physical_memory_offset, frame_allocator) {
        Some((entry, stack_top)) => Some((
            mapper,
            LoadedElf {
                page_table: l4_frame,
                entry,
                stack_top,
            },
        )),
        None => {
            unsafe { memory::free_address_space(l4_frame, physical_memory_offset, 0..0, frame_allocator) };
            None
        }
    }
}

/// The part of `load` that can fail partway through, once the fixed ELF
/// header is already validated and `new_address_space` has already built
/// a fresh (so far empty) address space for it — pulled out on its own so
/// `load` can free that address space on failure (`mapper` may already
/// have some segments mapped into it from earlier iterations) instead of
/// leaking it.
fn load_segments_and_stack(
    bytes: &[u8],
    mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Option<(VirtAddr, VirtAddr)> {
    let entry = read_u64(bytes, 0, 24)?;
    let phoff = read_u64(bytes, 0, 32)? as usize;
    let phentsize = read_u16(bytes, 0, 54)? as usize;
    let phnum = read_u16(bytes, 0, 56)? as usize;

    let mut highest_mapped = 0u64;

    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if read_u32(bytes, ph, 0)? != PT_LOAD {
            continue;
        }
        let p_flags = read_u32(bytes, ph, 4)?;
        let p_offset = read_u64(bytes, ph, 8)? as usize;
        let p_vaddr = read_u64(bytes, ph, 16)?;
        let p_filesz = read_u64(bytes, ph, 32)? as usize;
        let p_memsz = read_u64(bytes, ph, 40)?;

        let writable = p_flags & PF_W != 0;
        let file_end = p_offset.checked_add(p_filesz)?;
        let file_bytes = bytes.get(p_offset..file_end)?;
        map_segment(
            mapper,
            physical_memory_offset,
            frame_allocator,
            file_bytes,
            p_vaddr,
            p_memsz,
            writable,
        )?;

        highest_mapped = highest_mapped.max(p_vaddr.checked_add(p_memsz)?);
    }

    let stack_bottom = align_up(highest_mapped, PAGE_SIZE)?.checked_add(PAGE_SIZE)?;
    map_segment(mapper, physical_memory_offset, frame_allocator, &[], stack_bottom, STACK_SIZE, true)?;
    // 16-aligned, matching the same SysV requirement userspace.rs's hand
    // demos already have to satisfy. `VirtAddr::try_new` rather than
    // `::new`: both this and `entry` below are arithmetic on values that
    // ultimately trace back to attacker-controlled file content, so
    // either can land on a non-canonical address `::new` would panic on.
    let stack_top = VirtAddr::try_new(stack_bottom.checked_add(STACK_SIZE)?.checked_sub(16)?).ok()?;
    let entry = VirtAddr::try_new(entry).ok()?;

    Some((entry, stack_top))
}

fn align_up(addr: u64, align: u64) -> Option<u64> {
    Some(addr.checked_add(align - 1)? & !(align - 1))
}

/// Map `mem_size` bytes (rounded up to whole pages) at `vaddr`, copying
/// `file_bytes` in at the start and zero-filling the rest — the standard
/// ELF PT_LOAD behavior, where `p_memsz >= p_filesz` and the difference
/// (typically a segment's BSS) is expected to read as zero. Also used
/// (with `file_bytes` empty) to map the plain, zeroed stack page.
///
/// `None` — not a panic — for a `vaddr` that isn't page-aligned, or for a
/// `vaddr`/`mem_size` combination that overflows or lands at or above the
/// canonical-address boundary (bit 47 clear is required — `load`'s own
/// address-space bookkeeping does its highest-address/alignment
/// arithmetic on raw `u64`s and only calls `VirtAddr::try_new` at the
/// point each segment actually gets mapped; a load address right at or
/// above that boundary was found, empirically, to end up executing at
/// CPL 3 with a GPF rather than running, for reasons not fully traced to
/// a single line — this loader simply doesn't support it).
fn map_segment(
    mapper: &mut OffsetPageTable<'_>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    file_bytes: &[u8],
    vaddr: u64,
    mem_size: u64,
    writable: bool,
) -> Option<()> {
    if mem_size == 0 {
        return Some(());
    }
    if vaddr % PAGE_SIZE != 0 || vaddr >= 0x0000_8000_0000_0000 {
        return None;
    }

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }

    let last_byte = vaddr.checked_add(mem_size)?.checked_sub(1)?;
    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::try_new(vaddr).ok()?);
    let end_page = Page::<Size4KiB>::containing_address(VirtAddr::try_new(last_byte).ok()?);
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

    Some(())
}
