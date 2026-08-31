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

use alloc::vec::Vec;
use spin::Mutex;
use x86_64::structures::paging::FrameDeallocator;

/// A FrameAllocator that returns usable frames from the bootloader's memory
/// map, and can also take previously allocated frames back for reuse.
///
/// "Fresh" frames (never handed out before) come from `memory_map`, tracked
/// by `region_index`/`next_frame_addr` — a cursor that's simply advanced on
/// each allocation, rather than an iterator chain re-derived from scratch:
/// an earlier version did the latter (`.nth(next)` on every call), which
/// re-walked everything from the start each time — O(n) per call, O(n^2)
/// overall for n frames. A concrete cursor (rather than a stored `impl
/// Iterator`) is also what makes this type nameable in a `static`, which is
/// what lets `deallocate_frame` (reached from the scheduler's thread-exit
/// path, not just boot-time setup) share the same allocator state as
/// `allocate_frame` — see `FRAME_ALLOCATOR` below.
///
/// Freed frames go on `free_list` and are handed out again, most-recently-
/// freed first, before any fresh frame is ever touched. `free_list` starts
/// as `None` rather than `Vec::new()`: this allocator hands out the very
/// frames used to build the heap itself (`allocator::init_heap`, called
/// before the heap exists), so nothing on the fresh-allocation path may
/// itself allocate — the `Vec` is only created on the first *deallocation*,
/// by which point the heap is long since up.
pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    /// Index into `memory_map` of the region fresh frames are currently
    /// being handed out from.
    region_index: usize,
    /// The next not-yet-handed-out frame address within that region.
    /// Meaningless once `region_index` runs off the end of `memory_map`
    /// (nothing usable left).
    next_frame_addr: u64,
    free_list: Option<Vec<PhysFrame>>,
}

impl BootInfoFrameAllocator {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        let mut allocator = BootInfoFrameAllocator {
            memory_map,
            region_index: 0,
            next_frame_addr: 0,
            free_list: None,
        };
        allocator.skip_to_next_usable_region();
        allocator
    }

    /// Advance `region_index` (and prime `next_frame_addr`) to the next
    /// region in `memory_map`, starting from wherever it already is, that's
    /// actually `Usable` — called once at `init`, and again every time
    /// `allocate_frame` walks off the end of the region it was drawing
    /// from.
    fn skip_to_next_usable_region(&mut self) {
        while self.region_index < self.memory_map.len() {
            let region = &self.memory_map[self.region_index];
            if region.region_type == MemoryRegionType::Usable
                && region.range.start_addr() < region.range.end_addr()
            {
                self.next_frame_addr = region.range.start_addr();
                return;
            }
            self.region_index += 1;
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if let Some(frame) = self.free_list.as_mut().and_then(Vec::pop) {
            return Some(frame);
        }

        if self.region_index >= self.memory_map.len() {
            return None;
        }

        let frame = PhysFrame::containing_address(PhysAddr::new(self.next_frame_addr));
        self.next_frame_addr += 4096;
        if self.next_frame_addr >= self.memory_map[self.region_index].range.end_addr() {
            self.region_index += 1;
            self.skip_to_next_usable_region();
        }
        Some(frame)
    }
}

impl FrameDeallocator<Size4KiB> for BootInfoFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame) {
        self.free_list.get_or_insert_with(Vec::new).push(frame);
    }
}

/// The kernel's one and only physical-frame allocator, shared by every
/// piece of code that maps or unmaps memory — set up once in `kernel_main`
/// (`init_frame_allocator`) and reached from then on only through the
/// zero-sized `GlobalFrameAllocator` handle below.
///
/// Unlike `SCHEDULER` (src/scheduler/mod.rs), which was already a global
/// out of necessity (the timer ISR has to reach it from anywhere), this one
/// is global by choice: frames allocated for one isolated address space
/// (`elf::load`, boot-time demos) must be freed through the *same*
/// allocator state later, from `scheduler::reap_zombie`, which has no
/// relationship to whichever stack frame originally called `elf::load`. A
/// plain local variable threaded through every call site (as `kernel_main`
/// still does for the `OffsetPageTable` mapper) can't be reached from
/// there.
static FRAME_ALLOCATOR: Mutex<Option<BootInfoFrameAllocator>> = Mutex::new(None);

/// Install the global frame allocator. Must be called exactly once, during
/// boot, before anything calls `GlobalFrameAllocator` or `allocate_frame`/
/// `deallocate_frame` on it.
///
/// # Safety
/// Same requirement as `BootInfoFrameAllocator::init`: every frame marked
/// `Usable` in `memory_map` must really be unused.
pub unsafe fn init_frame_allocator(memory_map: &'static MemoryMap) {
    *FRAME_ALLOCATOR.lock() = Some(unsafe { BootInfoFrameAllocator::init(memory_map) });
}

/// A zero-sized handle onto the global frame allocator — implements
/// `FrameAllocator`/`FrameDeallocator` itself by locking `FRAME_ALLOCATOR`
/// for the duration of each call, so it can be passed anywhere an `impl
/// FrameAllocator<Size4KiB>` is expected (every existing call site in
/// `main.rs`/`userspace.rs`/`elf.rs` already takes one generically) without
/// those call sites needing to know the allocator behind it is global now.
pub struct GlobalFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for GlobalFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        FRAME_ALLOCATOR
            .lock()
            .as_mut()
            .expect("memory::init_frame_allocator was never called")
            .allocate_frame()
    }
}

impl FrameDeallocator<Size4KiB> for GlobalFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame) {
        unsafe {
            FRAME_ALLOCATOR
                .lock()
                .as_mut()
                .expect("memory::init_frame_allocator was never called")
                .deallocate_frame(frame)
        }
    }
}

/// The offset the bootloader maps all of physical memory at — set once
/// during boot (`set_physical_memory_offset`) alongside `memory::init`, and
/// read back later by `scheduler::reap_zombie`, which needs it to walk (and
/// free) an exited isolated thread's page tables but, unlike `kernel_main`,
/// has no local variable holding it.
static PHYSICAL_MEMORY_OFFSET: Mutex<Option<VirtAddr>> = Mutex::new(None);

pub fn set_physical_memory_offset(offset: VirtAddr) {
    *PHYSICAL_MEMORY_OFFSET.lock() = Some(offset);
}

pub fn physical_memory_offset() -> VirtAddr {
    PHYSICAL_MEMORY_OFFSET
        .lock()
        .expect("memory::set_physical_memory_offset was never called")
}

// ------------------------------------------------------------------
// Separate address spaces (real process isolation)
// ------------------------------------------------------------------

/// Build a fresh, mostly-empty top-level (L4) page table for an isolated
/// address space, and return both the physical frame holding it (to load
/// into CR3 later, when actually running something under it) and an
/// `OffsetPageTable` that can map pages into it *right now*, without ever
/// switching CR3.
///
/// That last part works because every address space this kernel creates
/// shares the exact same `physical_memory_offset` window over physical
/// RAM — so a frame belonging to the *new* table can still be reached
/// through the alias that's already active under the *current* one.
///
/// Two entries are copied in from the currently active L4 table before
/// anything else touches the new one: the one covering low memory (where
/// the kernel image itself, and identity-mapped regions like the VGA
/// buffer, live) and the one covering the physical-memory-offset window
/// itself (`OffsetPageTable` needs that mapping present in whichever table
/// is active in order to walk into it at all). Everything else — the
/// heap, every existing demo mapping — is deliberately left out: that's
/// what makes this a genuinely separate address space rather than just a
/// relabeled view of the same one. A process built on top of this can
/// only see what's explicitly mapped into it afterward.
///
/// # Safety
/// `physical_memory_offset` must be the same value passed to `memory::init`
/// (i.e. the whole of physical memory must really be mapped there), and
/// must currently be active (this reads the *active* L4 table via CR3).
pub unsafe fn new_address_space(
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> (PhysFrame, OffsetPageTable<'static>) {
    let new_l4_frame = frame_allocator
        .allocate_frame()
        .expect("no physical frames left for a new address space's L4 table");

    let new_l4_virt = physical_memory_offset + new_l4_frame.start_address().as_u64();
    let new_l4_ptr: *mut PageTable = new_l4_virt.as_mut_ptr();

    let new_l4_table: &'static mut PageTable = unsafe {
        new_l4_ptr.write(PageTable::new());
        &mut *new_l4_ptr
    };

    let active_l4_table = unsafe { active_level_4_table(physical_memory_offset) };

    // Index 0: low memory / the kernel image itself.
    new_l4_table[0] = active_l4_table[0].clone();
    // Whichever single entry covers physical_memory_offset. One L4 entry
    // spans 512 GiB, far more RAM than this kernel is ever run with, so
    // the offset window fitting inside just one entry is a safe
    // assumption here (rather than something to compute precisely from
    // the actual installed RAM).
    let offset_p4_index = usize::from(physical_memory_offset.p4_index());
    new_l4_table[offset_p4_index] = active_l4_table[offset_p4_index].clone();

    let mapper = unsafe { OffsetPageTable::new(new_l4_table, physical_memory_offset) };
    (new_l4_frame, mapper)
}

/// The counterpart to `new_address_space`: free every physical frame owned
/// exclusively by the isolated address space rooted at `l4_frame` — every
/// `PT_LOAD` segment `elf::load` mapped, the user stack it added, every
/// intermediate L3/L2/L1 table `map_to` allocated along the way to reach
/// any of those, and the L4 table itself — back to `frame_allocator` for
/// reuse. Called from `scheduler::reap_zombie` once an isolated thread has
/// exited for good.
///
/// The two L4 entries `new_address_space` cloned in from the kernel's own
/// table (index 0, and whichever index covers `physical_memory_offset`)
/// are deliberately skipped rather than walked into: they're shared with
/// the kernel's own address space (and every other isolated one), not
/// owned by this one, so freeing anything reachable through them would
/// pull frames out from under whichever address space is actually still
/// using them — that's the whole distinction `new_address_space`'s own doc
/// comment draws between "shared" and "everything else".
///
/// `borrowed_data_range` covers the one other kind of not-actually-owned
/// mapping an isolated address space can hold: `scheduler::spawn_isolated`
/// deliberately maps this thread's own *kernel*-mode stack — ordinary
/// kernel-heap memory, backed by frames the heap allocator (not
/// `frame_allocator`) is responsible for — into this table too, at whatever
/// virtual address `alloc::alloc::alloc` happened to place it. Its own
/// intermediate L3/L2/L1 tables really are private to this address space
/// (nothing else points at them) and get freed normally, but the *leaf*
/// frame each of those pages ultimately resolves to is the exact same
/// physical memory `reap_zombie` hands back to the heap allocator via a
/// separate `alloc::alloc::dealloc` call — so it must not *also* come back
/// through `frame_allocator` here, or the same physical frame ends up on
/// both allocators' free lists at once, double-issued to whichever one gets
/// asked for a frame next.
///
/// # Safety
/// `l4_frame` must be the L4 frame of an isolated address space built by
/// `new_address_space` (so its shared entries really are just clones, not
/// pointers to memory this address space owns), and must not be — and must
/// never again be — the active table in CR3 on this or any other CPU: every
/// frame this walks is hand back to `frame_allocator` for immediate reuse,
/// so any lingering reference to one (a stale TLB entry included) becomes a
/// use-after-free the instant something else is mapped over it.
/// `physical_memory_offset` must satisfy the same precondition as
/// `new_address_space`.
pub unsafe fn free_address_space(
    l4_frame: PhysFrame,
    physical_memory_offset: VirtAddr,
    borrowed_data_range: core::ops::Range<u64>,
    frame_allocator: &mut impl FrameDeallocator<Size4KiB>,
) {
    use x86_64::structures::paging::PageTableFlags;

    let l4_table = unsafe { table_at(l4_frame, physical_memory_offset) };
    let offset_p4_index = usize::from(physical_memory_offset.p4_index());

    for (i, entry) in l4_table.iter().enumerate() {
        if i == 0 || i == offset_p4_index {
            continue; // shared with the kernel's own address space — not owned by this one
        }
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        let l3_frame = entry.frame().expect("present L4 entry with no frame (huge page?)");
        let base_addr = (i as u64) << 39;
        unsafe {
            free_table(
                l3_frame,
                3,
                base_addr,
                physical_memory_offset,
                &borrowed_data_range,
                frame_allocator,
            )
        };
    }

    unsafe { frame_allocator.deallocate_frame(l4_frame) };
}

/// Reinterpret `frame` as a page table, through the physical-memory-offset
/// alias — the same access pattern `active_level_4_table` and
/// `new_address_space` already use, safe for the same reason: the whole of
/// physical memory is mapped there in every address space this kernel ever
/// builds, so this works no matter which table happens to be active in CR3
/// right now.
unsafe fn table_at(frame: PhysFrame, physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let virt = physical_memory_offset + frame.start_address().as_u64();
    unsafe { &mut *virt.as_mut_ptr::<PageTable>() }
}

/// Free an owned page-table subtree: every present entry in the table at
/// `frame` (an L3, L2, or L1 table, per `level` — 3, 2, or 1), and `frame`
/// itself. `level` distinguishes "this entry points at another table"
/// (levels 3 and 2, where every present entry gets walked into recursively)
/// from "this entry points at an actual data frame" (level 1, an L1/leaf
/// table, where every present entry is one of the pages `elf::map_segment`
/// or `scheduler::spawn_isolated` mapped) — the only structural difference
/// between the four page-table levels, once L4's own shared-vs-owned split
/// has already been handled by `free_address_space`'s caller.
///
/// `base_addr` is the virtual address prefix fixed by every index walked to
/// reach `frame` so far (the L4 index this descended from, shifted into
/// bits 39-47, then this table's own index at each recursive step) — kept
/// alongside the physical walk purely so a leaf entry's *virtual* address
/// can be checked against `borrowed_data_range` before deciding whether its
/// data frame is actually this address space's to free (see
/// `free_address_space`'s doc comment on `borrowed_data_range`). Plain
/// `u64` rather than `VirtAddr`: every value this builds is a 4 KiB-aligned
/// page address assembled purely from 9-bit table indices, so it's already
/// exactly what `VirtAddr::new` would return, without that constructor's
/// canonical-address check ever coming into it.
unsafe fn free_table(
    frame: PhysFrame,
    level: u8,
    base_addr: u64,
    physical_memory_offset: VirtAddr,
    borrowed_data_range: &core::ops::Range<u64>,
    frame_allocator: &mut impl FrameDeallocator<Size4KiB>,
) {
    use x86_64::structures::paging::PageTableFlags;

    let table = unsafe { table_at(frame, physical_memory_offset) };
    let shift = 12 + 9 * (level as u32 - 1);
    for (i, entry) in table.iter().enumerate() {
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        let child = entry.frame().expect("present page-table entry with no frame (huge page?)");
        let child_addr = base_addr | ((i as u64) << shift);
        if level > 1 {
            unsafe {
                free_table(
                    child,
                    level - 1,
                    child_addr,
                    physical_memory_offset,
                    borrowed_data_range,
                    frame_allocator,
                )
            };
        } else if !borrowed_data_range.contains(&child_addr) {
            unsafe { frame_allocator.deallocate_frame(child) };
        }
    }
    unsafe { frame_allocator.deallocate_frame(frame) };
}
