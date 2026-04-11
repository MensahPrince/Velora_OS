# Velora OS 🦀

A bare-metal x86_64 operating system kernel written in Rust — built as a study implementation following the **[Writing an OS in Rust](https://os.phil-opp.com/)** blog series by [Philipp Oppermann](https://github.com/phil-opp).

> **This is a learning project.** The goal is to deeply understand low-level systems programming concepts — memory management, hardware I/O, interrupts, and how an OS is structured — by building one from scratch.

---

## 📖 About

Velora OS is a `no_std` Rust kernel that runs directly on x86_64 hardware (or QEMU). It does not use Rust's standard library or any underlying OS — it *is* the OS.

This project follows the phil-opp tutorial series chapter by chapter, with additional personal notes baked into the source code as comments to reinforce understanding.

**Study Series:** https://os.phil-opp.com/

---

## ✅ Progress

| Chapter | Topic | Status |
|---|---|---|
| 1 | A Freestanding Rust Binary | ✅ Done |
| 2 | A Minimal Rust Kernel | ✅ Done |
| 3 | VGA Text Mode | ✅ Done |
| 4 | Testing | ✅ Done |
| 5 | CPU Exceptions & Interrupts (IDT) | ✅ Done |
| 6+ | Double Faults, Hardware Interrupts, ... | 🔄 In Progress |

---

## 🏗️ Project Structure

```
velora_os/
├── src/
│   ├── main.rs          # Kernel entry point (_start), panic handlers
│   ├── lib.rs           # Shared library: test infrastructure, QEMU exit
│   ├── vga_buffer.rs    # VGA text-mode driver (print! / println! macros)
│   ├── serial.rs        # UART serial port driver (serial_print! for tests)
│   └── interrupts.rs    # IDT setup and interrupt handlers (breakpoint, etc.)
├── tests/
│   └── basic_boot.rs    # Integration test: kernel boots and prints correctly
├── x86_64-velora_os.json  # Custom bare-metal target specification
├── .cargo/
│   └── config.toml      # Build target, bootimage runner, build-std config
└── Cargo.toml
```

---

## 🧰 Key Concepts Covered

- **`#![no_std]` / `#![no_main]`** — stripping away the standard library and Rust runtime
- **Custom linker target** (`x86_64-velora_os.json`) — targeting bare-metal x86_64
- **VGA Text Buffer** — writing to the screen at `0xb8000` using volatile writes and a global `Mutex`-protected writer
- **`lazy_static!`** — safely initializing global state in a `no_std` environment
- **Serial Port (UART 16550)** — outputting text to the host terminal for test output
- **Custom Test Framework** — running integration tests inside QEMU without `std`
- **Interrupt Descriptor Table (IDT)** — handling CPU exceptions (breakpoints, etc.) via the `x86-interrupt` ABI
- **QEMU Debug Exit** — cleanly shutting down QEMU from kernel code using I/O port `0xf4`

---

## 🚀 Running

### Prerequisites

- [Rust nightly toolchain](https://www.rust-lang.org/tools/install)
- [`bootimage`](https://github.com/rust-osdev/bootimage): `cargo install bootimage`
- [QEMU](https://www.qemu.org/): `sudo apt install qemu-system-x86`

```bash
# Install the nightly toolchain and required components
rustup override set nightly
rustup component add rust-src llvm-tools-preview
```

### Build & Run

```bash
# Run in QEMU
cargo run

# Run tests in QEMU (headless)
cargo test
```

---

## ⚙️ How It Works

```
Bootloader (BIOS/UEFI)
    └── bootimage (Rust bootloader crate)
        └── _start()  ←  first Rust code to execute
            ├── init()          → loads IDT
            ├── int3()          → triggers breakpoint exception (handled!)
            └── loop {}         → kernel idles forever
```

The kernel boots via the [`bootloader`](https://crates.io/crates/bootloader) crate, which sets up the CPU into 64-bit long mode before handing control to `_start()`.

---

## 📚 References

- **Primary tutorial:** https://os.phil-opp.com/
- [`x86_64` crate](https://crates.io/crates/x86_64) — safe abstractions over x86_64 hardware
- [`bootloader` crate](https://crates.io/crates/bootloader) — pure-Rust bootloader
- [`uart_16550` crate](https://crates.io/crates/uart_16550) — UART serial port driver
- [`lazy_static` crate](https://crates.io/crates/lazy_static) — runtime-initialized statics

---

## 📝 License

This project is for educational purposes. Code structure is derived from the [phil-opp/blog_os](https://github.com/phil-opp/blog_os) tutorial series, which is licensed under MIT / Apache 2.0.
