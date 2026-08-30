// ============================================================
// ata.rs
// A minimal ATA PIO (Programmed I/O) driver: enough to read sectors off
// either drive on the primary IDE bus, by polling. No interrupts, no
// writes, no drive identification — the standard legacy ATA I/O ports
// (0x1F0-0x1F7) work unchanged from 1990s hardware through today's
// chipsets running in IDE-compatibility mode, and QEMU emulates them for
// its `-drive` disks without any extra configuration. The master drive is
// the very same one this kernel itself boots from, which is what makes
// this driver's own first real test — reading sector 0 back and checking
// for the boot signature BIOS itself required to be there — a check
// against a real, independently-verifiable disk rather than something
// this driver invented for itself to pass. The slave drive carries no
// boot code at all; it exists purely to hold the FAT16 filesystem
// `src/fs.rs` reads from (see `Drive::Secondary`).
// ============================================================

use x86_64::instructions::port::Port;

const DATA: u16 = 0x1F0;
const SECTOR_COUNT: u16 = 0x1F2;
const LBA_LOW: u16 = 0x1F3;
const LBA_MID: u16 = 0x1F4;
const LBA_HIGH: u16 = 0x1F5;
const DRIVE_HEAD: u16 = 0x1F6;
const COMMAND_STATUS: u16 = 0x1F7;

const CMD_READ_SECTORS: u8 = 0x20;

const STATUS_ERR: u8 = 1 << 0;
const STATUS_DRQ: u8 = 1 << 3;
const STATUS_BSY: u8 = 1 << 7;

/// How many times to poll the status register before giving up on a drive
/// that never becomes ready. Not a real timeout (this driver has no clock
/// to measure against) — just an upper bound on how long a broken wait can
/// spin before turning into a clear panic instead of hanging forever.
///
/// The original value here (100_000) turned out to be a lot more marginal
/// than it looked: it broke when unrelated scheduler changes elsewhere in
/// the kernel shifted the compiled binary's timing enough to tip a
/// previously-comfortable margin into an occasional failure — without
/// changing anything about the ATA driver itself or the order it runs in.
/// A hardcoded iteration count is fundamentally a proxy for wall-clock
/// time, not a real one, and 100_000 iterations apparently wasn't enough
/// slack against that kind of incidental drift. This is generously larger
/// specifically so it stops being sensitive to that: even at this size, a
/// modern CPU (or QEMU's emulation of one) burns through it in a small
/// fraction of a second, so a genuinely broken drive still fails fast.
const POLL_ATTEMPTS: u32 = 10_000_000;

pub const SECTOR_SIZE: usize = 512;

/// Which of the two drives on the primary IDE bus to address. Both share
/// the same I/O ports (0x1F0-0x1F7) — only the drive-select bit written to
/// `DRIVE_HEAD` differs — so supporting a second disk doesn't need a
/// second bus's worth of ports, just this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drive {
    /// The disk this kernel itself boots from (QEMU's first `-drive`).
    Primary,
    /// A second disk attached purely for data (this kernel's FAT16
    /// filesystem lives here — see `src/fs.rs`), independent of the boot
    /// disk's own contents so the bootloader's sector-0 layout there is
    /// never disturbed.
    Secondary,
}

impl Drive {
    /// The drive-select nibble `read_sector` ORs into `DRIVE_HEAD`: bit 4
    /// clear selects the master drive, set selects the slave — the rest of
    /// the byte (bits 5,6,7 and the top LBA bits) is filled in by the
    /// caller.
    fn select_bit(self) -> u8 {
        match self {
            Drive::Primary => 0x00,
            Drive::Secondary => 0x10,
        }
    }
}

/// Read one 512-byte sector at LBA `lba` from `drive` into `buf`.
///
/// # Panics
/// If the drive reports an error, or never becomes ready. This is a
/// synchronous, polling-only driver with no way to report an I/O error
/// back to a caller yet — the same "fail loudly with a clear message"
/// choice this kernel already makes elsewhere for infrastructure that
/// isn't expected to fail under normal conditions (e.g. the frame
/// allocator running out of memory). A real block-device abstraction that
/// returns `Result` is natural follow-up work once something actually
/// needs to recover from a bad read instead of just reporting one.
pub fn read_sector(drive: Drive, lba: u32, buf: &mut [u8; SECTOR_SIZE]) {
    assert!(lba < (1 << 28), "LBA28 only supports 28-bit sector addresses");

    unsafe {
        wait_until_not_busy();

        // 0xE0: LBA mode, plus the drive-select bit, plus the top 4 bits of
        // the LBA (bits 24-27) in the low nibble.
        Port::<u8>::new(DRIVE_HEAD).write(0xE0 | drive.select_bit() | ((lba >> 24) & 0x0F) as u8);
        Port::<u8>::new(SECTOR_COUNT).write(1);
        Port::<u8>::new(LBA_LOW).write((lba & 0xFF) as u8);
        Port::<u8>::new(LBA_MID).write(((lba >> 8) & 0xFF) as u8);
        Port::<u8>::new(LBA_HIGH).write(((lba >> 16) & 0xFF) as u8);
        Port::<u8>::new(COMMAND_STATUS).write(CMD_READ_SECTORS);

        wait_for_data();

        // The data port is 16 bits wide; a 512-byte sector is 256 words.
        let mut data_port = Port::<u16>::new(DATA);
        for word_bytes in buf.chunks_exact_mut(2) {
            let word = data_port.read();
            word_bytes[0] = (word & 0xFF) as u8;
            word_bytes[1] = (word >> 8) as u8;
        }
    }
}

/// # Safety
/// Must only be called with exclusive access to the ATA I/O ports for the
/// duration — true today since this whole driver is synchronous and
/// nothing else touches these ports.
unsafe fn wait_until_not_busy() {
    let mut status_port = Port::<u8>::new(COMMAND_STATUS);
    for _ in 0..POLL_ATTEMPTS {
        if unsafe { status_port.read() } & STATUS_BSY == 0 {
            return;
        }
    }
    panic!("ATA: drive stayed busy for too long");
}

/// # Safety
/// Same requirement as `wait_until_not_busy`.
unsafe fn wait_for_data() {
    let mut status_port = Port::<u8>::new(COMMAND_STATUS);
    for _ in 0..POLL_ATTEMPTS {
        let status = unsafe { status_port.read() };
        if status & STATUS_ERR != 0 {
            panic!("ATA: drive reported an error (status {:#x})", status);
        }
        if status & STATUS_BSY == 0 && status & STATUS_DRQ != 0 {
            return;
        }
    }
    panic!("ATA: drive never became ready to transfer data");
}
