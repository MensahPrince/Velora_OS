// ============================================================
// fs.rs
// A minimal, read-only FAT16 driver: enough to look a file up by its 8.3
// name in the root directory and read its full contents back, from the
// second IDE drive (`ata::Drive::Secondary`, see src/ata.rs). No writes,
// no subdirectories, no long filenames — the smallest real subset of a
// real, widely-documented on-disk format that can actually load a file.
//
// FAT16 (rather than a from-scratch format) is deliberate: the disk image
// itself is built by real host tooling (`mkfs.fat`, `mtools` — see
// build.rs) rather than by this kernel, so this driver's own first real
// test is the same shape as ata.rs's own: reading back something a
// completely independent, well-known implementation wrote, not just
// something this driver invented for itself to pass.
// ============================================================

use crate::ata::{self, Drive, SECTOR_SIZE};
use alloc::vec::Vec;

/// The whole filesystem lives on the secondary drive — the boot disk
/// (`Drive::Primary`) is left untouched, still just the bootloader/kernel
/// image it always was.
const FS_DRIVE: Drive = Drive::Secondary;

/// A FAT16 directory entry is fixed at 32 bytes regardless of the field
/// contents (8.3 name, attributes, timestamps, first cluster, size).
const DIR_ENTRY_SIZE: usize = 32;

/// The first byte of a directory entry's name field when the entry is
/// unused (deleted, or past the last real entry) — the FAT spec's
/// "nothing more to see here" markers.
const DIR_ENTRY_FREE: u8 = 0xE5;
const DIR_ENTRY_END: u8 = 0x00;

/// The attribute byte value used for VFAT long-filename entries, which
/// this driver deliberately doesn't understand — they're laid out as
/// otherwise-plausible-looking directory entries with this exact
/// attribute combination, so skipping any entry with these bits set is
/// what keeps a long-named file from being misread as a garbled 8.3 one.
const ATTR_LONG_NAME: u8 = 0x0F;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// The handful of BIOS Parameter Block fields this driver actually needs,
/// parsed fresh from the boot sector on every lookup — cheap enough (one
/// sector read) that there's no reason to cache it, and it sidesteps ever
/// needing a `once`-style global for filesystem state.
struct BiosParameterBlock {
    reserved_sector_count: u16,
    num_fats: u8,
    root_entry_count: u16,
    fat_size_sectors: u16,
    sectors_per_cluster: u8,
}

impl BiosParameterBlock {
    /// `None` if the boot sector doesn't look like a 512-byte-sector FAT16
    /// volume this driver understands — including the harmless case where
    /// the secondary drive has no filesystem on it at all (e.g. a dev
    /// machine that hasn't run `build.rs`'s FAT-image step because
    /// `mkfs.fat`/`mtools` aren't installed): a boot sector of all zeroes
    /// reads back as `bytes_per_sector == 0`, which just fails this check
    /// like any other malformed BPB rather than needing a separate case.
    fn parse(boot_sector: &[u8; SECTOR_SIZE]) -> Option<Self> {
        let bytes_per_sector = read_u16(boot_sector, 0x0B);
        if bytes_per_sector as usize != SECTOR_SIZE {
            return None;
        }

        Some(Self {
            reserved_sector_count: read_u16(boot_sector, 0x0E),
            num_fats: boot_sector[0x10],
            root_entry_count: read_u16(boot_sector, 0x11),
            fat_size_sectors: read_u16(boot_sector, 0x16),
            sectors_per_cluster: boot_sector[0x0D],
        })
    }

    fn first_fat_sector(&self) -> u32 {
        self.reserved_sector_count as u32
    }

    /// The root directory, on FAT16, is a fixed-size run of sectors right
    /// after the FATs — not itself a cluster chain the way subdirectories
    /// are, which is exactly what lets this driver get away with never
    /// having implemented cluster-chain directory reading at all.
    fn root_dir_sector_count(&self) -> u32 {
        let root_dir_bytes = self.root_entry_count as u32 * DIR_ENTRY_SIZE as u32;
        root_dir_bytes.div_ceil(SECTOR_SIZE as u32)
    }

    fn first_root_dir_sector(&self) -> u32 {
        self.first_fat_sector() + self.num_fats as u32 * self.fat_size_sectors as u32
    }

    fn first_data_sector(&self) -> u32 {
        self.first_root_dir_sector() + self.root_dir_sector_count()
    }

    /// Cluster numbering starts at 2 (0 and 1 are reserved FAT entries),
    /// so the data region's very first cluster — number 2 — maps to its
    /// very first sector, with no gap.
    fn cluster_to_lba(&self, cluster: u16) -> u32 {
        self.first_data_sector() + (cluster as u32 - 2) * self.sectors_per_cluster as u32
    }
}

fn read_sector(lba: u32) -> [u8; SECTOR_SIZE] {
    let mut buf = [0u8; SECTOR_SIZE];
    ata::read_sector(FS_DRIVE, lba, &mut buf);
    buf
}

/// Format an 8.3 name (`"ECHO.ELF"`, case-insensitive) into FAT's own
/// fixed 11-byte, space-padded, uppercase on-disk representation
/// (`"ECHO    ELF"`), so a directory entry's raw name bytes can be
/// compared against it directly.
fn to_fat_83(name: &str) -> Option<[u8; 11]> {
    let (base, ext) = match name.split_once('.') {
        Some((base, ext)) => (base, ext),
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return None;
    }

    let mut fat_name = [b' '; 11];
    for (i, b) in base.bytes().enumerate() {
        fat_name[i] = b.to_ascii_uppercase();
    }
    for (i, b) in ext.bytes().enumerate() {
        fat_name[8 + i] = b.to_ascii_uppercase();
    }
    Some(fat_name)
}

struct DirEntry {
    first_cluster: u16,
    file_size: u32,
}

/// Scan the (fixed-size, non-cluster-chained) root directory for `name`,
/// reading it one sector at a time straight off disk — small enough on
/// any FAT16 volume this driver would realistically be pointed at that
/// there's no benefit to reading it in bulk first.
fn find_in_root_dir(bpb: &BiosParameterBlock, name: &[u8; 11]) -> Option<DirEntry> {
    let first_sector = bpb.first_root_dir_sector();
    let sector_count = bpb.root_dir_sector_count();

    'sectors: for i in 0..sector_count {
        let sector = read_sector(first_sector + i);
        for entry in sector.chunks_exact(DIR_ENTRY_SIZE) {
            match entry[0] {
                DIR_ENTRY_END => break 'sectors,
                DIR_ENTRY_FREE => continue,
                _ => {}
            }
            let attributes = entry[0x0B];
            if attributes == ATTR_LONG_NAME || attributes & ATTR_VOLUME_ID != 0 {
                continue;
            }
            if attributes & ATTR_DIRECTORY != 0 {
                continue; // no subdirectory traversal — root dir only
            }
            if &entry[0..11] == name {
                return Some(DirEntry {
                    first_cluster: read_u16(entry, 0x1A),
                    file_size: read_u32(entry, 0x1C),
                });
            }
        }
    }
    None
}

/// Look up the FAT entry for `cluster` — the 16-bit slot, at
/// `first_fat_sector + (cluster * 2) / 512`, that holds either the next
/// cluster in this file's chain or one of FAT16's reserved
/// end-of-chain/bad-cluster markers.
fn next_cluster(bpb: &BiosParameterBlock, cluster: u16) -> Option<u16> {
    let fat_byte_offset = cluster as u32 * 2;
    let sector = bpb.first_fat_sector() + fat_byte_offset / SECTOR_SIZE as u32;
    let offset_in_sector = (fat_byte_offset % SECTOR_SIZE as u32) as usize;

    let fat_sector = read_sector(sector);
    let entry = read_u16(&fat_sector, offset_in_sector);

    // 0xFFF8-0xFFFF: end of chain. 0xFFF7: bad cluster — treated the same
    // as end-of-chain here (no error path back to the caller yet, same
    // "fail loudly or stop" tradeoff ata.rs makes; a genuinely bad cluster
    // in the middle of a file just means the read comes back short).
    if entry >= 0xFFF8 || entry == 0xFFF7 {
        None
    } else {
        Some(entry)
    }
}

/// Read the full contents of `name` (an 8.3 filename, case-insensitive —
/// e.g. `"ECHO.ELF"`) from the root directory of the filesystem disk.
/// Returns `None` if no such file exists, or if the secondary drive
/// doesn't hold a FAT16 filesystem this driver recognizes at all (see
/// `BiosParameterBlock::parse`) — deliberately not a hard failure, since
/// that's the expected state on a dev machine that hasn't built `fs.img`
/// yet (see `build.rs`).
///
/// # Panics
/// If `name` isn't representable as an 8.3 name (longer than 8 characters
/// before the dot, or more than 3 after it) — this driver has no long-
/// filename support, so such a name could never have matched anything
/// found on disk anyway.
pub fn read_file(name: &str) -> Option<Vec<u8>> {
    let fat_name = to_fat_83(name).expect("fs: not a representable 8.3 filename");

    let boot_sector = read_sector(0);
    let bpb = BiosParameterBlock::parse(&boot_sector)?;

    let entry = find_in_root_dir(&bpb, &fat_name)?;

    let mut data = Vec::with_capacity(entry.file_size as usize);
    let mut cluster = entry.first_cluster;

    // A zero-length file has no cluster chain to walk (first_cluster is 0,
    // which isn't a valid data cluster) — the loop below would try to read
    // cluster 0 and misbehave, so it's short-circuited here instead.
    if entry.file_size == 0 {
        return Some(data);
    }

    loop {
        let first_lba = bpb.cluster_to_lba(cluster);
        for i in 0..bpb.sectors_per_cluster as u32 {
            let sector = read_sector(first_lba + i);
            let remaining = entry.file_size as usize - data.len();
            let take = remaining.min(SECTOR_SIZE);
            data.extend_from_slice(&sector[..take]);
            if data.len() >= entry.file_size as usize {
                return Some(data);
            }
        }

        cluster = match next_cluster(&bpb, cluster) {
            Some(next) => next,
            None => return Some(data), // chain ended short of file_size
        };
    }
}
