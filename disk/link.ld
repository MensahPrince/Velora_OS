/* ============================================================
 * link.ld
 * A linker script for disk/echo.s (see build.rs) that forces every
 * section into a single PT_LOAD segment, page-aligned and RWX.
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
 * ============================================================ */

ENTRY(_start)

PHDRS
{
    combined PT_LOAD FLAGS(7); /* rwx */
}

SECTIONS
{
    . = 0x400000;
    .text   : { *(.text) }   :combined
    .rodata : { *(.rodata) } :combined
    .bss    : { *(.bss) }    :combined
    /DISCARD/ : { *(.note*) *(.comment) *(.eh_frame) }
}
