// ============================================================
// build.rs
// Builds the second virtual disk (`fs.img`) that src/fs.rs's FAT16 driver
// reads from: assembles and links every program in disk/ (see
// DISK_PROGRAMS below) into real, freestanding ELF64 executables with the
// host toolchain (`as`/`ld` — cross-compiling *for the host*, not this
// kernel's own custom target, since this code never runs inside the
// kernel itself), then packs them onto a freshly formatted FAT16 image
// using `mkfs.fat` and `mtools` — real, independent tools building the
// filesystem's on-disk bytes, the same "check against something that
// isn't this kernel's own code" reasoning src/ata.rs's own top-of-file
// comment already lays out for the boot disk itself.
//
// `fs.img` is written straight into the crate root (not `OUT_DIR`)
// because `Cargo.toml`'s `[package.metadata.bootimage] run-args` needs a
// stable, fixed path to hand QEMU as a second `-drive` — an `OUT_DIR`
// path changes with the build hash. It's a generated artifact, not
// source, so it's `.gitignore`d and rebuilt here on every build (assuming
// disk/echo.s or disk/link.ld changed) rather than being checked in.
//
// This step is deliberately non-fatal if the host is missing `as`/`ld`
// (essentially never, since they ship with any Rust toolchain's linker)
// or `mkfs.fat`/`mtools` (plausible — they're not a normal Rust
// dependency): `cargo test`'s QEMU invocation never attaches the second
// drive at all (see Cargo.toml's `test-args` vs `run-args`), so tests
// must keep working with no `fs.img` present. `cargo run` does attach it
// unconditionally, so a placeholder (unformatted, all-zero) image is
// still written even when the real toolchain is missing — QEMU needs
// *a* file to exist there regardless, and src/fs.rs already treats an
// unrecognized boot sector as "no filesystem found" rather than panicking
// (see `BiosParameterBlock::parse`).
// ============================================================

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 16 MiB: comfortably large enough for `mkfs.fat -F16` to accept without
/// falling back to FAT12 (which has a much smaller volume-size ceiling),
/// while staying small enough that formatting and copying a single small
/// test binary onto it is effectively instant on every build.
const FS_IMAGE_SIZE_BYTES: u64 = 16 * 1024 * 1024;

/// Every disk-resident assembly program this kernel ships, as (source file
/// stem, 8.3 name to give it on `fs.img`) — all built the same way (`as`,
/// then `ld` against the shared `disk/link.ld`), just for different actual
/// programs, so `build_fs_image` just loops over this rather than
/// hand-duplicating the same six lines once per program.
const DISK_PROGRAMS: &[(&str, &str)] = &[
    ("echo", "ECHO.ELF"),
    ("greet", "GREET.ELF"),
    ("shell", "SHELL.ELF"),
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let link_script = manifest_dir.join("disk/link.ld");
    let fs_image = manifest_dir.join("fs.img");

    // Deliberately NOT watching `fs.img` itself here (only the real
    // inputs): `mkfs.fat` gives the volume a fresh random serial number on
    // every run, so its mtime changes every time this script writes it —
    // watching it would make Cargo see its own output as "changed" after
    // every single build and rerun this script (and recompile the kernel
    // crate right along with it) forever, on every build, even when
    // nothing real changed. The tradeoff: if `fs.img` is ever deleted by
    // hand without touching a `disk/*.s` source, it won't come back on its
    // own until something else invalidates the build (e.g. `touch
    // disk/echo.s`, or a clean build) — an acceptable gap for a file
    // nothing but this script is expected to ever remove.
    for (stem, _) in DISK_PROGRAMS {
        println!(
            "cargo:rerun-if-changed={}",
            manifest_dir.join("disk").join(format!("{stem}.s")).display()
        );
    }
    println!("cargo:rerun-if-changed={}", link_script.display());
    println!("cargo:rerun-if-changed=build.rs");

    if let Err(reason) = build_fs_image(&manifest_dir, &link_script, &out_dir, &fs_image) {
        println!(
            "cargo:warning=fs.img: skipping FAT16 disk image build ({reason}); \
             writing a blank placeholder instead. Install `as`/`ld` (binutils) \
             and `mkfs.fat`/`mcopy` (dosfstools + mtools) and rebuild to get a \
             real filesystem `cargo run` can load from (see src/fs.rs)."
        );
        write_placeholder_image(&fs_image);
    }
}

fn build_fs_image(
    manifest_dir: &Path,
    link_script: &Path,
    out_dir: &Path,
    fs_image: &Path,
) -> Result<(), String> {
    for tool in ["as", "ld", "mkfs.fat", "mcopy"] {
        which(tool).ok_or_else(|| format!("`{tool}` not found on PATH"))?;
    }

    write_placeholder_image(fs_image);
    run(Command::new("mkfs.fat")
        .args(["-F", "16", "-n", "VELORAFS"])
        .arg(fs_image))?;

    for (stem, fat_name) in DISK_PROGRAMS {
        let asm_src = manifest_dir.join("disk").join(format!("{stem}.s"));
        let object = out_dir.join(format!("{stem}.o"));
        let elf = out_dir.join(format!("{stem}.elf"));

        run(Command::new("as").args(["--64", "-o"]).arg(&object).arg(&asm_src))?;
        run(Command::new("ld")
            .args(["-static", "-nostdlib", "-T"])
            .arg(link_script)
            .arg("-o")
            .arg(&elf)
            .arg(&object))?;
        run(Command::new("mcopy")
            .arg("-i")
            .arg(fs_image)
            .arg(&elf)
            .arg(format!("::{fat_name}")))?;
    }

    // A plain-text file — for `userspace::spawn_open_read_demo`
    // (src/userspace.rs) to open and read back through a real ring-3
    // syscall::SYS_OPEN/SYS_READ round trip and print, proving that path
    // end to end with genuinely printable output. ECHO.ELF itself would
    // technically work too (fs::read_file doesn't care what kind of file
    // it's handed), but its bytes are machine code, not valid UTF-8 —
    // sys_write would just report "invalid utf-8" instead of anything a
    // human can actually read as confirmation.
    let hello_txt = out_dir.join("hello.txt");
    std::fs::write(&hello_txt, HELLO_TXT_CONTENTS)
        .map_err(|e| format!("failed to write {}: {e}", hello_txt.display()))?;
    run(Command::new("mcopy")
        .arg("-i")
        .arg(fs_image)
        .arg(&hello_txt)
        .arg("::HELLO.TXT"))?;

    Ok(())
}

/// Kept in sync with `userspace::OPEN_READ_DEMO_READ_LEN` (src/userspace.rs)
/// — that demo's read buffer must be at least this long, or its one read()
/// call won't come back with the whole message.
const HELLO_TXT_CONTENTS: &[u8] = b"hello from the on-disk filesystem, opened via sys_open\n";

/// A fixed-size, all-zero file — not a valid FAT16 volume (its "boot
/// sector" reads back as `bytes_per_sector == 0`), but enough for QEMU to
/// attach as a `-drive` without erroring, and the starting point
/// `mkfs.fat` itself formats in place.
fn write_placeholder_image(path: &Path) {
    let file = std::fs::File::create(path)
        .unwrap_or_else(|e| panic!("fs.img: failed to create {}: {e}", path.display()));
    file.set_len(FS_IMAGE_SIZE_BYTES)
        .unwrap_or_else(|e| panic!("fs.img: failed to size {}: {e}", path.display()));
}

fn which(tool: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    env::split_paths(&path_var)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
}

fn run(command: &mut Command) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|e| format!("failed to run {command:?}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{command:?} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}
