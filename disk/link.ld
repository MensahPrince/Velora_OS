/* ============================================================
 * link.ld
 * A linker script shared by every disk-resident test program (disk/echo.s,
 * disk/greet.s — see build.rs) that forces every section into a single
 * PT_LOAD segment, page-aligned and RWX.
 *
 * The default linker behavior splits code and data into separate PT_LOAD
 * segments whenever their permissions differ, and only page-aligns the
 * split between *executable* and *non-executable* regions (via
 * `-z separate-code`) — a writable section (like .bss) tucked after a
 * read-only one still lands at a sub-page-aligned virtual address. That's
 * exactly what src/elf.rs's loader doesn't support (it deliberately
 * requires every PT_LOAD's p_vaddr to be page-aligned — seeing multiple
 * PT_LOAD segments share one physical page, with different permissions
 * each expects to apply to their own share of it, is real complexity a
 * "smallest real subset" loader was never meant to take on). Merging
 * everything into one segment sidesteps that entirely: one page-aligned
 * p_vaddr, one permission (RWX — this kernel doesn't enable NX yet
 * either, so nothing meaningfully enforces W^X regardless).
 *
 * The load address itself (below) has to stay well above the low-memory
 * region every isolated address space shares with the kernel's own table
 * (`memory::new_address_space` clones that single L4 *entry* rather than
 * deep-copying it, so every address space with something mapped there is
 * actually sharing one physical L3 subtree) — two programs both linked at
 * a low address, loaded into two different address spaces at different
 * times, would silently collide in that shared subtree instead of getting
 * the private mappings isolation is supposed to guarantee. This is
 * exactly what happened when disk/greet.s was first added, also at the
 * traditional low ELF default of 0x400000: loading it after disk/echo.s
 * had already populated that shared region failed with
 * `MapToError::PageAlreadyMapped`. A high address, in a P4 slot nothing
 * else in this kernel uses (matching every other demo's own address
 * choice — see src/userspace.rs), sidesteps the sharing entirely: each
 * address space gets a genuinely private subtree there.
 * ============================================================ */

ENTRY(_start)

PHDRS
{
    combined PT_LOAD FLAGS(7); /* rwx */
}

SECTIONS
{
    . = 0x7F0000000000;
    .text   : { *(.text) }   :combined
    .rodata : { *(.rodata) } :combined
    .bss    : { *(.bss) }    :combined
    /DISCARD/ : { *(.note*) *(.comment) *(.eh_frame) }
}
