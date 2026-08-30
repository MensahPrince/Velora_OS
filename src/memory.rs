// ============================================================
// memory.rs
// Handles physical/virtual memory mapping for Velora_OS.
// ============================================================

use x86_64::{
    structures::paging::PageTable,
    VirtAddr,
};

// OffsetPageTable is a higher-level abstraction provided by the x86_64 crate.
// Instead of manually walking the 4-level page table ourselves, we hand it
// a pointer to the L4 table and the physical memory offset, and it handles
// all the traversal internally. This is the approach recommended once the
// manual walk (translate_addr_inner) has been understood.
use x86_64::structures::paging::OffsetPageTable;

/// Initialize a new OffsetPageTable.
///
/// Internally this calls `active_level_4_table` (now private) to get a
/// `&mut PageTable` reference, then wraps it in an `OffsetPageTable`.
/// The `OffsetPageTable` implements the `Translate` trait, which lets us
/// call `mapper.translate_addr(virt)` instead of doing the 4-level walk
/// ourselves.
///
/// # Safety
/// The caller must guarantee that the complete physical memory is mapped
/// to virtual memory at `physical_memory_offset`. Must only be called
/// once to avoid aliasing `&mut` references (undefined behaviour).
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    unsafe {
        // Grab a mutable reference to the active L4 page table, then wrap
        // it. From this point on, `OffsetPageTable` owns the walk logic.
        let level_4_table = active_level_4_table(physical_memory_offset);
        OffsetPageTable::new(level_4_table, physical_memory_offset)
    }
}
// active_level_4_table is intentionally private — callers should go through
// `init()` and use the `OffsetPageTable` interface instead of holding a raw
// mutable reference to the L4 table.
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr)
    -> &'static mut PageTable
{
    use x86_64::registers::control::Cr3;

    // CR3 always holds the physical address of the currently active L4 table.
    let (level_4_table_frame, _) = Cr3::read();

    // We can't dereference a physical address directly — convert it to the
    // corresponding virtual address using the offset the bootloader gave us.
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    // Safety: the caller guarantees the offset mapping is correct and that
    // this function is called only once (no aliasing).
    unsafe { &mut *page_table_ptr }
}

use x86_64::PhysAddr;

// ------------------------------------------------------------------
// Manual address translation (kept for reference / learning purposes)
// ------------------------------------------------------------------
// NOTE: In the current kernel we now use `OffsetPageTable::translate_addr`
// (via the `Translate` trait) instead of calling this directly. The manual
// implementation below is preserved so you can see exactly what the
// `OffsetPageTable` abstraction is doing under the hood.

/// Translates the given virtual address to the mapped physical address, or
/// `None` if the address is not mapped.
///
/// # Safety
/// The caller must guarantee that the complete physical memory is mapped
/// to virtual memory at `physical_memory_offset`. The caller must also
/// guarantee that no `OffsetPageTable` created via `memory::init` (or any
/// other live `&mut PageTable` over the same L4 table) is in use at the same
/// time: this function independently re-reads CR3 and re-derives page-table
/// references from scratch, so calling it while a mapper is alive creates
/// aliased references to the same page tables, which is undefined behaviour.
pub unsafe fn translate_addr(addr: VirtAddr, physical_memory_offset: VirtAddr)
    -> Option<PhysAddr>
{
    translate_addr_inner(addr, physical_memory_offset)
}


/// Private function that is called by `translate_addr`.
///
/// This function is safe to limit the scope of `unsafe` because Rust treats
/// the whole body of unsafe functions as an unsafe block. This function must
/// only be reachable through `unsafe fn` from outside of this module.
fn translate_addr_inner(addr: VirtAddr, physical_memory_offset: VirtAddr)
    -> Option<PhysAddr>
{
    use x86_64::structures::paging::page_table::FrameError;
    use x86_64::registers::control::Cr3;

    // read the active level 4 frame from the CR3 register
    let (level_4_table_frame, _) = Cr3::read();

    let table_indexes = [
        addr.p4_index(), addr.p3_index(), addr.p2_index(), addr.p1_index()
    ];
    let mut frame = level_4_table_frame;

    // traverse the multi-level page table
    for &index in &table_indexes {
        // convert the frame into a page table reference
        let virt = physical_memory_offset + frame.start_address().as_u64();
        let table_ptr: *const PageTable = virt.as_ptr();
        let table = unsafe {&*table_ptr};

        // read the page table entry and update `frame`
        let entry = &table[index];
        frame = match entry.frame() {
            Ok(frame) => frame,
            Err(FrameError::FrameNotPresent) => return None,
            Err(FrameError::HugeFrame) => panic!("huge pages not supported"),
        };
    }

    // calculate the physical address by adding the page offset
    Some(frame.start_address() + u64::from(addr.page_offset()))
}



use x86_64:: structures::paging::{
    Page, PhysFrame, Mapper, Size4KiB, FrameAllocator
};

/// A FrameAllocator that always returns `None`.
pub struct EmptyFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for EmptyFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        None
    }
}


/// Creates an example mapping for the given page to frame `0xb8000`.
pub fn create_example_mapping(
    page: Page,
    mapper: &mut OffsetPageTable,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    use x86_64::structures::paging::PageTableFlags as Flags;

    let frame = PhysFrame::containing_address(PhysAddr::new(0xb8000));
    let flags = Flags::PRESENT | Flags::WRITABLE;

    let map_to_result = unsafe {
        // FIXME: this is not safe, we do it only for testing
        mapper.map_to(page, frame, flags, frame_allocator)
    };
    map_to_result.expect("map_to failed").flush();
}

// in src/memory.rs

use bootloader::bootinfo::MemoryMap;

use bootloader::bootinfo::MemoryRegionType;

/// A FrameAllocator that returns usable frames from the bootloader's memory map.
///
/// The filtered/flattened iterator over usable frames is built once (in
/// `init`) and then simply advanced on each allocation. An earlier version
/// re-derived that iterator from the raw memory map and called `.nth(next)`
/// on every `allocate_frame`, which re-walked everything from the start each
/// time — O(n) per call, O(n^2) overall for n frames.
pub struct BootInfoFrameAllocator<I: Iterator<Item = PhysFrame>> {
    frames: I,
}

impl BootInfoFrameAllocator<core::iter::Empty<PhysFrame>> {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    pub unsafe fn init(
        memory_map: &'static MemoryMap,
    ) -> BootInfoFrameAllocator<impl Iterator<Item = PhysFrame>> {
        // get usable regions from memory map
        let regions = memory_map.iter();
        let usable_regions = regions
            .filter(|r| r.region_type == MemoryRegionType::Usable);
        // map each region to its address range
        let addr_ranges = usable_regions
            .map(|r| r.range.start_addr()..r.range.end_addr());
        // transform to an iterator of frame start addresses, then to `PhysFrame`s
        let frames = addr_ranges
            .flat_map(|r| r.step_by(4096))
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)));

        BootInfoFrameAllocator { frames }
    }
}

unsafe impl<I: Iterator<Item = PhysFrame>> FrameAllocator<Size4KiB> for BootInfoFrameAllocator<I> {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        self.frames.next()
    }
}
