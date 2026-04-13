/// VHD footer and MBR generation for mounting decrypted volumes as Windows drives.
/// Pure byte manipulation — no external dependencies.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const PARTITION_OFFSET: u64 = 1024 * 1024; // 1MB alignment

/// Create a VHD file from a decrypted stream.
/// The VHD contains: MBR (512 bytes) + padding to 1MB + filesystem data + VHD footer.
/// The `progress` callback receives values from 0.0 to 1.0 indicating copy progress.
pub fn create_vhd<S: Read + Seek, W: Write + Seek>(
    decrypted_stream: &mut S,
    vhd_out: &mut W,
    progress: &dyn Fn(f64),
) -> io::Result<()> {
    let data_size = decrypted_stream.seek(SeekFrom::End(0))?;
    decrypted_stream.seek(SeekFrom::Start(0))?;

    let disk_size = (PARTITION_OFFSET + data_size + 511) & !511;

    // Write MBR
    let mbr = create_mbr(PARTITION_OFFSET, data_size, disk_size);
    vhd_out.write_all(&mbr)?;

    // Padding to partition offset
    let padding = vec![0u8; (PARTITION_OFFSET - 512) as usize];
    vhd_out.write_all(&padding)?;

    // Copy decrypted filesystem data
    let mut buffer = vec![0u8; 64 * 1024];
    let mut remaining = data_size as i64;
    let mut bytes_written: u64 = 0;
    while remaining > 0 {
        let to_read = buffer.len().min(remaining as usize);
        let n = decrypted_stream.read(&mut buffer[..to_read])?;
        if n == 0 {
            break;
        }
        vhd_out.write_all(&buffer[..n])?;
        remaining -= n as i64;
        bytes_written += n as u64;
        if data_size > 0 {
            progress(bytes_written as f64 / data_size as f64);
        }
    }

    // Pad to full disk size
    let current_pos = vhd_out.seek(SeekFrom::Current(0))?;
    if current_pos < disk_size {
        let pad = vec![0u8; (disk_size - current_pos) as usize];
        vhd_out.write_all(&pad)?;
    }

    // Write VHD footer at the end
    let footer = create_vhd_footer(disk_size);
    vhd_out.write_all(&footer)?;
    vhd_out.flush()?;

    Ok(())
}

/// Read partition data back from a VHD file (skip MBR + alignment).
/// Used during write-back after unmount.
pub fn read_vhd_partition<R: Read + Seek>(
    vhd: &mut R,
    data_size: u64,
) -> io::Result<Vec<u8>> {
    vhd.seek(SeekFrom::Start(PARTITION_OFFSET))?;
    let mut data = vec![0u8; data_size as usize];
    vhd.read_exact(&mut data)?;
    Ok(data)
}

/// The offset where partition data starts in the VHD.
pub fn partition_offset() -> u64 {
    PARTITION_OFFSET
}

fn create_mbr(partition_offset: u64, partition_size: u64, _disk_size: u64) -> [u8; 512] {
    let mut mbr = [0u8; 512];
    let pe = 446; // Partition entry starts at offset 446

    mbr[pe] = 0x00; // Not active/bootable

    // CHS of first sector (LBA mode: 0xFE, 0xFF, 0xFF)
    mbr[pe + 1] = 0xFE;
    mbr[pe + 2] = 0xFF;
    mbr[pe + 3] = 0xFF;

    mbr[pe + 4] = 0x07; // Partition type: NTFS/exFAT/HPFS

    // CHS of last sector
    mbr[pe + 5] = 0xFE;
    mbr[pe + 6] = 0xFF;
    mbr[pe + 7] = 0xFF;

    // LBA of first sector (little-endian u32)
    let lba_start = (partition_offset / 512) as u32;
    mbr[pe + 8] = lba_start as u8;
    mbr[pe + 9] = (lba_start >> 8) as u8;
    mbr[pe + 10] = (lba_start >> 16) as u8;
    mbr[pe + 11] = (lba_start >> 24) as u8;

    // Number of sectors in partition (little-endian u32)
    let sector_count = (partition_size / 512) as u32;
    mbr[pe + 12] = sector_count as u8;
    mbr[pe + 13] = (sector_count >> 8) as u8;
    mbr[pe + 14] = (sector_count >> 16) as u8;
    mbr[pe + 15] = (sector_count >> 24) as u8;

    // Boot signature
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    mbr
}

fn create_vhd_footer(disk_size: u64) -> [u8; 512] {
    let mut footer = [0u8; 512];

    // Cookie: "conectix"
    footer[0..8].copy_from_slice(b"conectix");

    // Features: 0x00000002 (Reserved, must be set)
    footer[11] = 0x02;

    // File Format Version: 0x00010000 (1.0)
    footer[13] = 0x01;

    // Data Offset: 0xFFFFFFFFFFFFFFFF (fixed disk, no dynamic header)
    footer[16..24].fill(0xFF);

    // Timestamp: seconds since Jan 1, 2000 12:00:00 UTC
    let epoch_2000 = 946684800u64; // Unix timestamp for 2000-01-01 00:00:00 UTC
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let timestamp = (now.saturating_sub(epoch_2000)) as u32;
    write_be32(&mut footer, 24, timestamp);

    // Creator Application: "tcdr" (TC Drive Reader)
    footer[28..32].copy_from_slice(b"tcdr");

    // Creator Version: 1.0
    footer[33] = 0x01;

    // Creator Host OS: Windows ("Wi2k")
    footer[36..40].copy_from_slice(&[0x57, 0x69, 0x32, 0x6B]);

    // Original Size (big-endian u64)
    write_be64(&mut footer, 40, disk_size);

    // Current Size (big-endian u64)
    write_be64(&mut footer, 48, disk_size);

    // Disk Geometry (CHS)
    let (cylinders, heads, sectors_per_track) = compute_chs(disk_size);
    footer[56] = (cylinders >> 8) as u8;
    footer[57] = cylinders as u8;
    footer[58] = heads;
    footer[59] = sectors_per_track;

    // Disk Type: Fixed (0x00000002)
    footer[63] = 0x02;

    // Unique ID (16 bytes) — simple pseudo-random from timestamp
    let seed = now ^ (disk_size.wrapping_mul(0x517cc1b727220a95));
    for i in 0..16 {
        footer[68 + i] = ((seed >> ((i % 8) * 8)) ^ (i as u64 * 37)) as u8;
    }

    // Saved State: 0 (already zero)

    // Compute checksum (one's complement of sum of all bytes, skipping checksum field at 64..68)
    let mut checksum: u32 = 0;
    for (i, &byte) in footer.iter().enumerate() {
        if i >= 64 && i < 68 {
            continue;
        }
        checksum = checksum.wrapping_add(byte as u32);
    }
    checksum = !checksum;
    write_be32(&mut footer, 64, checksum);

    footer
}

fn compute_chs(disk_size: u64) -> (u16, u8, u8) {
    let mut total_sectors = disk_size / 512;

    if total_sectors > 65535 * 16 * 255 {
        total_sectors = 65535 * 16 * 255;
    }

    let cylinders: u16;
    let heads: u8;
    let sectors_per_track: u8;

    if total_sectors >= 65535 * 16 * 63 {
        sectors_per_track = 255;
        heads = 16;
        cylinders = (total_sectors / (16 * 255)) as u16;
    } else {
        let mut spt = 17u64;
        let mut tmp = total_sectors / spt;
        let mut h = ((tmp + 1023) / 1024).max(4);

        if tmp >= h * 1024 || h > 16 {
            spt = 31;
            h = 16;
            tmp = total_sectors / spt;
        }

        if tmp >= h * 1024 {
            spt = 63;
            h = 16;
            tmp = total_sectors / spt;
        }

        sectors_per_track = spt as u8;
        heads = h as u8;
        cylinders = (tmp / h).min(65535) as u16;
    }

    (cylinders, heads, sectors_per_track)
}

fn write_be32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset] = (value >> 24) as u8;
    buf[offset + 1] = (value >> 16) as u8;
    buf[offset + 2] = (value >> 8) as u8;
    buf[offset + 3] = value as u8;
}

fn write_be64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset] = (value >> 56) as u8;
    buf[offset + 1] = (value >> 48) as u8;
    buf[offset + 2] = (value >> 40) as u8;
    buf[offset + 3] = (value >> 32) as u8;
    buf[offset + 4] = (value >> 24) as u8;
    buf[offset + 5] = (value >> 16) as u8;
    buf[offset + 6] = (value >> 8) as u8;
    buf[offset + 7] = value as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mbr_boot_signature() {
        let mbr = create_mbr(1024 * 1024, 10 * 1024 * 1024, 11 * 1024 * 1024);
        assert_eq!(mbr[510], 0x55);
        assert_eq!(mbr[511], 0xAA);
    }

    #[test]
    fn test_mbr_partition_type() {
        let mbr = create_mbr(1024 * 1024, 10 * 1024 * 1024, 11 * 1024 * 1024);
        assert_eq!(mbr[446 + 4], 0x07); // NTFS type
    }

    #[test]
    fn test_mbr_lba_start() {
        let mbr = create_mbr(1024 * 1024, 10 * 1024 * 1024, 11 * 1024 * 1024);
        let lba = u32::from_le_bytes([mbr[454], mbr[455], mbr[456], mbr[457]]);
        assert_eq!(lba, 2048); // 1MB / 512
    }

    #[test]
    fn test_vhd_footer_cookie() {
        let footer = create_vhd_footer(100 * 1024 * 1024);
        assert_eq!(&footer[0..8], b"conectix");
    }

    #[test]
    fn test_vhd_footer_disk_type_fixed() {
        let footer = create_vhd_footer(100 * 1024 * 1024);
        let disk_type = u32::from_be_bytes([footer[60], footer[61], footer[62], footer[63]]);
        assert_eq!(disk_type, 2); // Fixed
    }

    #[test]
    fn test_vhd_footer_size_roundtrip() {
        let size: u64 = 256 * 1024 * 1024;
        let footer = create_vhd_footer(size);
        let original = u64::from_be_bytes(footer[40..48].try_into().unwrap());
        let current = u64::from_be_bytes(footer[48..56].try_into().unwrap());
        assert_eq!(original, size);
        assert_eq!(current, size);
    }

    #[test]
    fn test_compute_chs_small_disk() {
        let (c, h, s) = compute_chs(100 * 1024 * 1024);
        assert!(c > 0);
        assert!(h >= 4);
        assert!(s > 0);
    }

    #[test]
    fn test_compute_chs_large_disk() {
        let (c, h, s) = compute_chs(500u64 * 1024 * 1024 * 1024);
        assert_eq!(h, 16);
        assert_eq!(s, 255);
        assert!(c <= 65535);
    }

    #[test]
    fn test_vhd_footer_checksum_valid() {
        let footer = create_vhd_footer(100 * 1024 * 1024);
        // Verify: one's complement of (sum of all bytes except checksum) == stored checksum
        let stored_checksum = u32::from_be_bytes([footer[64], footer[65], footer[66], footer[67]]);
        let mut sum: u32 = 0;
        for (i, &b) in footer.iter().enumerate() {
            if i >= 64 && i < 68 { continue; }
            sum = sum.wrapping_add(b as u32);
        }
        assert_eq!(stored_checksum, !sum);
    }
}
