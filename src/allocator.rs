// in src/allocator.rs


use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub const HEAP_START: u64 = 0x4444_4444_0000;
// Bumped from the original 100 KiB: two 16 KiB kernel-thread stacks
// (src/scheduler) plus the scancode/task-executor queues and the boot-time
// demo allocations no longer fit comfortably in 100 KiB. Bumped again, from
// 1 MiB, alongside `scheduler::STACK_SIZE` quadrupling (16 KiB -> 64 KiB —
// see that constant's own doc comment for why): `MAX_THREADS` stacks at the
// new size could theoretically approach 1 MiB on their own, before anything
// else this kernel puts on the heap. 4 MiB is still tiny next to real RAM
// and leaves real headroom for more threads later.
pub const HEAP_SIZE: u64 = 4 * 1024 * 1024; // 4 MiB

// in src/allocator.rs

use x86_64::{
    VirtAddr,
    structures::paging::{
        FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB, mapper::MapToError,
    },
};

pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe { mapper.map_to(page, frame, flags, frame_allocator)?.flush() };
    }

    unsafe {
        ALLOCATOR
            .lock()
            .init(HEAP_START as usize, HEAP_SIZE as usize);
    }

    Ok(())
}
