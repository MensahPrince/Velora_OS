# Velora OS

A bare-metal x86-64 operating system kernel implemented in Rust, developed as an independent systems-programming study. The project originated as an implementation of Philipp Oppermann's *[Writing an OS in Rust](https://os.phil-opp.com/)* series and has since been extended substantially beyond that series' scope to include preemptive multitasking, ring-3 execution with genuine address-space isolation, a register-based system-call interface, an ELF64 loader, and disk I/O.

## Abstract

Velora OS is a `no_std`, `no_main` freestanding kernel targeting x86-64 in BIOS long mode. It implements, from first principles, the core subsystems of a conventional monolithic kernel: physical and virtual memory management, interrupt and exception handling, a preemptive round-robin scheduler, cooperative asynchronous task execution, a minimal process model with hardware-enforced memory isolation, a system-call ABI, and a loader for a constrained subset of the ELF64 executable format. Every subsystem is implemented without external kernel frameworks; hardware interfacing (paging structures, the GDT/IDT/TSS, the PIC, and the legacy ATA interface) is programmed directly against the relevant Intel/AMD and device specifications.

## Motivation

The project exists to develop a rigorous, from-scratch understanding of the mechanisms an operating system kernel depends on: how a CPU transitions between privilege levels, how virtual memory is constructed and isolated between execution contexts, how preemption is implemented at the instruction level, and how these mechanisms compose into something resembling a real kernel. Bugs encountered during development — several of which manifested only under specific timing or address conditions in QEMU — are treated as primary material for that understanding rather than incidental noise; where instructive, their root causes and fixes are documented in the source itself.

## System Architecture

### Boot and Memory Management

- The kernel is loaded by the [`bootloader`](https://crates.io/crates/bootloader) crate (BIOS boot path), which establishes 64-bit long mode and maps all physical memory at a fixed offset before transferring control to `_start`.
- Virtual memory is managed through a 4-level paging hierarchy accessed via the `x86_64` crate's `OffsetPageTable` abstraction, addressing physical frames through that bootloader-provided offset.
- A fixed-size heap (`linked_list_allocator`) backs all dynamic allocation (`alloc::boxed::Box`, `Vec`, `Rc`, and the kernel's own internal data structures).
- **Isolated address spaces.** `memory::new_address_space` constructs an independent top-level (L4) page table for a process, sharing only the kernel code/data region and the physical-memory offset window with the kernel's own table. No other mapping is inherited, so a process's memory is genuinely unreachable from any other address space, including the kernel's default one — verified directly by querying the kernel's own page tables for a process's memory and confirming no translation exists.

### Interrupts and Exceptions

- A hand-populated Interrupt Descriptor Table handles CPU exceptions (breakpoint, double fault, page fault, general protection fault) with diagnostic output — faulting address, error code, and interrupt frame — and all sixteen legacy PIC interrupt lines, preventing an unhandled hardware interrupt from escalating into an unrecoverable triple fault.
- The Task State Segment provides a dedicated stack for double-fault handling (via the Interrupt Stack Table) and the privilege-transition stack (`RSP0`) used whenever a ring-3-to-ring-0 transition occurs.

### Concurrency

- **Preemptive scheduling.** A round-robin scheduler switches between kernel threads on every timer interrupt. Context switches are implemented as a hand-written, register-preserving routine (`scheduler::context::switch_to`) that also performs the CR3 (address-space) switch as an atomic part of the same operation — necessary because no intervening memory access is safe between changing the active page table and changing the stack pointer.
- **Cooperative tasks.** An async/await executor (`task::executor`), driven by `core::task::Waker`, runs as the workload of a single scheduled thread, providing non-blocking I/O multiplexing (e.g. the keyboard input task) without busy-polling.
- Data structures reachable from interrupt context (the scheduler's ready queue, the keyboard input queue) are deliberately implemented as fixed-capacity, statically allocated ring buffers rather than heap-backed collections: an interrupt can be delivered while an isolated process's address space is active, and such an address space does not map the kernel heap.

### Privilege Isolation and System Calls

- The kernel constructs ring-3 (user-mode) GDT segments and transitions execution to CPL 3 via a manually constructed `IRETQ` frame.
- A register-based system-call ABI is exposed through a software interrupt (`int 0x80`), serviced by a hand-written entry stub that preserves the full general-purpose register set. This is necessary because the `x86-interrupt` calling convention cannot expose arbitrary registers to handler code: the compiler's generated prologue relocates them before user code runs. Two calls are currently implemented: `write(fd, buf, len)` and `read(fd, buf, len)`.

### Process Loading

- `elf::load` parses the ELF64 file and program-header tables of a static, non-relocatable executable, maps its `PT_LOAD` segments into a freshly constructed isolated address space with permissions derived from `p_flags`, zero-fills the BSS region, and allocates a user-mode stack.

### Storage I/O

- `ata::read_sector` implements polling-mode Programmed I/O against the legacy primary ATA interface (I/O ports `0x1F0`-`0x1F7`), sufficient to read arbitrary LBA28 sectors from the boot disk.

## Project Structure

```
velora_os/
├── src/
│   ├── main.rs          Kernel entry point, panic handlers, demonstration routines
│   ├── lib.rs            Library root: test harness, QEMU exit, initialization
│   ├── gdt.rs             Global Descriptor Table, Task State Segment
│   ├── interrupts.rs      Interrupt Descriptor Table and exception/IRQ handlers
│   ├── memory.rs          Paging, frame allocation, isolated address spaces
│   ├── allocator.rs       Heap initialization
│   ├── scheduler/         Preemptive round-robin scheduler and context switching
│   ├── task/              Async executor and cooperative task infrastructure
│   ├── syscall.rs         System-call entry point and dispatch
│   ├── userspace.rs       Ring-3 demonstration payloads
│   ├── elf.rs             ELF64 loader
│   ├── ata.rs             ATA PIO disk driver
│   ├── vga_buffer.rs      VGA text-mode output driver
│   └── serial.rs          UART 16550 serial output driver
├── tests/                 Integration tests (executed inside QEMU)
├── x86_64-velora_os.json  Custom bare-metal target specification
└── .cargo/config.toml     Build configuration (target, build-std, QEMU runner)
```

## Build and Execution

### Toolchain

This kernel targets an unstable subset of the Rust compiler (`build-std`, naked functions, the `x86-interrupt` ABI) and is consequently sensitive to nightly-compiler drift; a specific nightly release is pinned:

```bash
rustup override set nightly-2026-05-01
rustup component add rust-src llvm-tools-preview
cargo install bootimage
```

`qemu-system-x86_64` must be available on `PATH`.

### Running

```bash
cargo run     # boot the kernel in QEMU
cargo test    # execute the integration test suite (headless)
```

## Implementation Status

| Subsystem | State |
|---|---|
| Freestanding boot, VGA/serial output | Implemented |
| Paging, heap allocation | Implemented |
| CPU exception handling, hardware interrupts | Implemented |
| Preemptive scheduling | Implemented |
| Cooperative async task execution | Implemented |
| Ring-3 execution | Implemented |
| Isolated address spaces (per-process paging) | Implemented |
| System-call interface | Implemented (`read`, `write`) |
| ELF64 loading | Implemented (static `PT_LOAD` executables only) |
| Disk I/O | Implemented (PIO sector reads only) |
| Filesystem | Not implemented |
| Process lifecycle (spawn/exit) | Not implemented |

## Known Limitations

- **Single concurrent ring-3 thread.** The privilege-transition stack (`TSS.RSP0`) is a single, statically allocated region shared by every thread; running two ring-3 threads concurrently corrupts this shared state. A per-thread `RSP0`, swapped by the scheduler alongside the CR3 switch, is the identified fix and has not yet been implemented.
- **ELF loader constraints.** Only statically linked, non-PIE executables with page-aligned `PT_LOAD` segments are supported; there is no relocation processing, dynamic linking, or section-header parsing.
- **No filesystem.** The ATA driver reads raw sectors only; there is no partition table or filesystem parser, so loading an arbitrary file from disk is not yet possible.
- **No NX enforcement.** `EFER.NXE` is not enabled, so the page table's `NO_EXECUTE` bit is not currently meaningful.
- **No process termination.** Threads, once spawned, are not reclaimed; there is no `exit` system call or scheduler-level cleanup path.

## Future Work

In approximate dependency order: a per-thread privilege-transition stack, removing the single-ring-3-thread constraint; a minimal filesystem sufficient to load an ELF binary from disk rather than an embedded test payload; process lifecycle management (`exit`, and eventually `fork`/`exec`-equivalent primitives); and an expanded system-call surface.

## References

- P. Oppermann, *[Writing an OS in Rust](https://os.phil-opp.com/)* — the tutorial series this project originated from; covers freestanding binaries through async/await task execution.
- *Intel 64 and IA-32 Architectures Software Developer's Manuals* — paging, interrupt/exception handling, segmentation, and privilege-level transitions.
- [`x86_64` crate](https://crates.io/crates/x86_64) — safe(r) abstractions over the structures above.
- [`bootloader` crate](https://crates.io/crates/bootloader) — the BIOS bootloader used to enter long mode.
- *AT Attachment (ATA/ATAPI) specification* — the legacy PIO command interface implemented in `src/ata.rs`.
- [*Executable and Linkable Format (ELF) specification*](https://refspecs.linuxfoundation.org/elf/elf.pdf) — the binary format implemented, as a subset, in `src/elf.rs`.

## License

This project is released for educational and research purposes. Portions of its structure derive from the [`phil-opp/blog_os`](https://github.com/phil-opp/blog_os) tutorial series (MIT / Apache 2.0).
