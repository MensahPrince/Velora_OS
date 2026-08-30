// ============================================================
// build.rs
// Builds the second virtual disk (`fs.img`) that src/fs.rs's FAT16 driver
// reads from: assembles and links disk/echo.s into a real, freestanding
// ELF64 executable with the host toolchain (`as`/`ld` — cross-compiling
// *for the host*, not this kernel's own custom target, since this code
// never runs inside the kernel itself), then packs it onto a freshly
// formatted FAT16 image using `mkfs.fat` and `mtools` — real, independent
// tools building the filesystem's on-disk bytes, the same "check against
// something that isn't this kernel's own code" reasoning src/ata.rs's own
// top-of-file comment already lays out for the boot disk itself.
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

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let asm_src = manifest_dir.join("disk/echo.s");
    let link_script = manifest_dir.join("disk/link.ld");
    let fs_image = manifest_dir.join("fs.img");

    // Deliberately NOT watching `fs.img` itself here (only the real
    // inputs): `mkfs.fat` gives the volume a fresh random serial number on
    // every run, so its mtime changes every time this script writes it —
    // watching it would make Cargo see its own output as "changed" after
    // every single build and rerun this script (and recompile the kernel
    // crate right along with it) forever, on every build, even when
    // nothing real changed. The tradeoff: if `fs.img` is ever deleted by
    // hand without touching `disk/echo.s`, it won't come back on its own
    // until something else invalidates the build (e.g. `touch
    // disk/echo.s`, or a clean build) — an acceptable gap for a file nothing
    // but this script is expected to ever remove.
    println!("cargo:rerun-if-changed={}", asm_src.display());
    println!("cargo:rerun-if-changed={}", link_script.display());
    println!("cargo:rerun-if-changed=build.rs");

    if let Err(reason) = build_fs_image(&asm_src, &link_script, &out_dir, &fs_image) {
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
    asm_src: &Path,
    link_script: &Path,
    out_dir: &Path,
    fs_image: &Path,
) -> Result<(), String> {
    for tool in ["as", "ld", "mkfs.fat", "mcopy"] {
        which(tool).ok_or_else(|| format!("`{tool}` not found on PATH"))?;
    }

    let object = out_dir.join("echo.o");
    let elf = out_dir.join("echo.elf");

    run(Command::new("as").args(["--64", "-o"]).arg(&object).arg(asm_src))?;
    run(Command::new("ld")
        .args(["-static", "-nostdlib", "-T"])
        .arg(link_script)
        .arg("-o")
        .arg(&elf)
        .arg(&object))?;

    write_placeholder_image(fs_image);
    run(Command::new("mkfs.fat")
        .args(["-F", "16", "-n", "VELORAFS"])
        .arg(fs_image))?;
    run(Command::new("mcopy")
        .arg("-i")
        .arg(fs_image)
        .arg(&elf)
        .arg("::ECHO.ELF"))?;

    Ok(())
}

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
