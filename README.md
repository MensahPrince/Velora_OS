# Velora OS

A bare-metal x86-64 operating system kernel implemented in Rust, developed as an independent systems-programming study. The project originated as an implementation of Philipp Oppermann's *[Writing an OS in Rust](https://os.phil-opp.com/)* series and has since been extended substantially beyond that series' scope to include preemptive multitasking, ring-3 execution with genuine address-space isolation, a register-based system-call interface, an ELF64 loader, and disk I/O.

## Abstract

Velora OS is a `no_std`, `no_main` freestanding kernel targeting x86-64 in BIOS long mode. It implements, from first principles, the core subsystems of a conventional monolithic kernel: physical and virtual memory management, interrupt and exception handling, a preemptive round-robin scheduler, cooperative asynchronous task execution, a minimal process model with hardware-enforced memory isolation, a system-call ABI, a loader for a constrained subset of the ELF64 executable format, and a read-only FAT16 filesystem sufficient to load that ELF64 executable from an actual disk. Every subsystem is implemented without external kernel frameworks; hardware interfacing (paging structures, the GDT/IDT/TSS, the PIC, and the legacy ATA interface) is programmed directly against the relevant Intel/AMD and device specifications.

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
- A register-based system-call ABI is exposed through a software interrupt (`int 0x80`), serviced by a hand-written entry stub that preserves the full general-purpose register set. This is necessary because the `x86-interrupt` calling convention cannot expose arbitrary registers to handler code: the compiler's generated prologue relocates them before user code runs. Seven calls are currently implemented: `write(fd, buf, len)`, `read(fd, buf, len)`, `exit()`, `open(path, path_len)`, `close(fd)`, `spawn(path, path_len)`, and `wait(pid)`. `open` looks a file up by path through `fs::read_file` and buffers its full contents (this filesystem driver has no partial/streaming read of its own) in a per-thread file-descriptor table — capped at a small, fixed number of slots per thread, and reachable only by the thread that opened it — so an isolated process can't see or exhaust another's open files, the same isolation this kernel already enforces for memory; `read` on a returned fd slices out of that buffer, and any files still open at exit are freed automatically alongside the rest of that thread's own state.
- `spawn` is what lets a *running* ring-3 program launch another one by path — every process before it was spawned directly by kernel boot code (`main.rs` calling `elf::load`/`scheduler::spawn_isolated` itself), never by another running program. It loads the named file through `fs::read_file` and `elf::load` and starts it as a new isolated thread (`scheduler::spawn_user`), returning a `Pid` a caller can pass to `wait` to block until that thread exits (no real blocking primitive exists yet, so `wait` polls `scheduler::thread_alive` in a `yield_now` loop — invisible to the caller, which just sees an ordinary syscall that takes a while to return). Not real `fork()`: it never duplicates the calling process's own memory the way a true fork would, only ever loading and running a *different* program from a path — closer to `posix_spawn`, and deliberately so, since a shell needs to launch other programs rather than clone itself, and true `fork` would additionally need copy-on-write address-space duplication this kernel has no machinery for at all. `elf::load` itself had to be hardened alongside this: it used to `panic!` on a malformed file, an accepted shortcut while the only ELF binaries it ever parsed were ones this kernel (or its own build scripts) built; `spawn` can now hand it an arbitrary file a ring-3 program named by path, so every parsing failure — truncated file, out-of-range program header, an offset/size that would overflow — returns `None` instead, freeing whatever partial address space had already been built rather than leaking it.
- Every syscall argument that's actually a pointer into the caller's own address space is validated before use (`syscall::copy_from_user`/`copy_to_user`), rather than trusted outright: each walks the calling thread's own page table — the right one to check, since `int 0x80` never switches CR3 — confirming every page the argument's range touches is really mapped and accessible from CPL 3 (and, for a write destination, actually writable) at *every* level of the walk, not just the leaf, matching how the CPU itself evaluates access permissions. Before this, a bad pointer from a ring-3 program would page-fault straight into a kernel panic, one process's mistake taking the whole kernel down with it. Now it kills just the offending thread (`scheduler::kill_current_thread`, reusing the same reclamation path as a voluntary `exit()`) and the kernel keeps running — proven by a ring-3 demo that deliberately calls `write` with an unmapped address and confirms the kernel survives it.

### Process Loading and Lifecycle

- `elf::load` parses the ELF64 file and program-header tables of a static, non-relocatable executable, maps its `PT_LOAD` segments into a freshly constructed isolated address space with permissions derived from `p_flags`, zero-fills the BSS region, and allocates a user-mode stack.
- `scheduler::exit_current_thread` (reachable from kernel-mode thread bodies directly, or from ring 3 via `syscall::SYS_EXIT`) removes a thread from the round-robin rotation for good and frees its kernel stack, making its slot in the scheduler's fixed-size thread table available for reuse. A thread can't free the stack it's still executing on, so cleanup is deferred one scheduling event, to whichever *other* thread's own call into the scheduler runs next (`reap_zombie`), never to the exiting thread itself. If the exiting thread was isolated (`spawn_isolated`), `reap_zombie` also walks and frees its entire address space (`memory::free_address_space`) — every `PT_LOAD` segment, its user stack, and every intermediate page-table frame allocated to reach them — back to a global, reusable `BootInfoFrameAllocator` (`memory::GlobalFrameAllocator`), skipping only what that address space never owned in the first place: the kernel-shared L4 entries `new_address_space` cloned in, and the thread's own kernel-mode stack, which `spawn_isolated` deliberately dual-maps into it but which belongs to the ordinary heap allocator, not the frame allocator.

### Storage I/O and Filesystem

- `ata::read_sector` implements polling-mode Programmed I/O against the legacy primary ATA interface (I/O ports `0x1F0`-`0x1F7`), sufficient to read arbitrary LBA28 sectors from either drive on that bus (`ata::Drive::Primary`/`Secondary`, selected via the drive-select bit — no second bus's worth of ports needed).
- `fs::read_file` implements a minimal, read-only FAT16 driver: BIOS Parameter Block parsing, root-directory 8.3-name lookup, and cluster-chain following, sufficient to read a whole file back from the secondary drive. That drive carries a filesystem entirely independent of the boot disk (`ata::Drive::Primary`, whose sector 0 is still just the bootloader), built by real host tooling (`mkfs.fat`, `mtools`) rather than by this kernel itself — see `build.rs`.
- `build.rs` assembles a small real userspace program (`disk/echo.s`, linked via `disk/link.ld` into a static, non-PIE ELF64 executable using the host's own `as`/`ld`) and copies it onto a freshly formatted FAT16 image (`fs.img`) as `ECHO.ELF`, attached to QEMU as the secondary drive. `main.rs` reads it back through `fs::read_file` and the real ELF loader (`elf::load`) at boot — the same read/write ring-3 echo demo the other loader demo runs, but arrived at via an actual on-disk file rather than one embedded in the kernel image.

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
│   ├── ata.rs             ATA PIO disk driver (primary + secondary drive)
│   ├── fs.rs              Read-only FAT16 filesystem driver
│   ├── vga_buffer.rs      VGA text-mode output driver
│   └── serial.rs          UART 16550 serial output driver
├── disk/                  Source for the on-disk test program (see build.rs)
│   ├── echo.s              Freestanding x86-64 ring-3 test program
│   └── link.ld              Linker script forcing a single page-aligned PT_LOAD
├── build.rs               Assembles disk/echo.s and builds fs.img (FAT16 image)
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

`qemu-system-x86_64` must be available on `PATH`. Building the filesystem test image (`fs.img`, via `build.rs`) additionally needs `mkfs.fat`/`mcopy` (`dosfstools` + `mtools`); if they're missing, the build still succeeds (with a warning) and `cargo run` boots with a blank secondary disk instead — `fs::read_file` reports no filesystem found rather than panicking.

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
| System-call interface | Implemented (`read`, `write`, `exit`, `open`, `close`, `spawn`, `wait`) |
| ELF64 loading | Implemented (static `PT_LOAD` executables only) |
| Disk I/O | Implemented (PIO sector reads, primary + secondary drive) |
| Filesystem | Implemented (read-only FAT16: file lookup by 8.3 name, cluster-chain reads) |
| Process lifecycle (spawn/exit) | Implemented (thread-table slot, kernel-stack, and — for isolated processes — full address-space reclamation on exit) |

## Known Limitations

- **ELF loader constraints.** Only statically linked, non-PIE executables with page-aligned `PT_LOAD` segments are supported; there is no relocation processing, dynamic linking, or section-header parsing.
- **Filesystem constraints.** `fs.rs` is read-only, FAT16-only (no FAT12/32), root-directory-only (no subdirectories), and 8.3-name-only (no long filenames) — enough to look up and read back a single flat file, not a general-purpose filesystem.
- **No NX enforcement.** `EFER.NXE` is not enabled, so the page table's `NO_EXECUTE` bit is not currently meaningful.

## Future Work

In approximate dependency order: a real interactive shell built on top of `syscall::SYS_SPAWN`/`SYS_WAIT` (a program that reads a command line and launches it, rather than every ring-3 program still being one of a fixed handful of boot-time demos); true `fork()` (copy-on-write address-space duplication — `SYS_SPAWN` deliberately doesn't attempt this, see its own doc comment); killing just the offending process, rather than only ending its current syscall, on other classes of fault beyond a bad syscall pointer; and, further out, filesystem writes and subdirectory support.

## References

- P. Oppermann, *[Writing an OS in Rust](https://os.phil-opp.com/)* — the tutorial series this project originated from; covers freestanding binaries through async/await task execution.
- *Intel 64 and IA-32 Architectures Software Developer's Manuals* — paging, interrupt/exception handling, segmentation, and privilege-level transitions.
- [`x86_64` crate](https://crates.io/crates/x86_64) — safe(r) abstractions over the structures above.
- [`bootloader` crate](https://crates.io/crates/bootloader) — the BIOS bootloader used to enter long mode.
- *AT Attachment (ATA/ATAPI) specification* — the legacy PIO command interface implemented in `src/ata.rs`.
- *Microsoft FAT specification* — the on-disk BIOS Parameter Block, directory-entry, and cluster-chain layout implemented, read-only, in `src/fs.rs`.
- [*Executable and Linkable Format (ELF) specification*](https://refspecs.linuxfoundation.org/elf/elf.pdf) — the binary format implemented, as a subset, in `src/elf.rs`.

## License

This project is released for educational and research purposes. Portions of its structure derive from the [`phil-opp/blog_os`](https://github.com/phil-opp/blog_os) tutorial series (MIT / Apache 2.0).
