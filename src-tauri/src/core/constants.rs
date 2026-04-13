/// TrueCrypt volume format constants.
/// Matches TrueCrypt 7.1a source (Crypto.h, Volumes.h, Password.h).

// Volume header sizes
pub const VOLUME_HEADER_SIZE: usize = 64 * 1024; // TC_VOLUME_HEADER_SIZE
pub const VOLUME_HEADER_EFFECTIVE_SIZE: usize = 512; // TC_VOLUME_HEADER_EFFECTIVE_SIZE
pub const VOLUME_HEADER_GROUP_SIZE: usize = 2 * VOLUME_HEADER_SIZE; // TC_VOLUME_HEADER_GROUP_SIZE
pub const VOLUME_DATA_OFFSET: u64 = VOLUME_HEADER_GROUP_SIZE as u64; // TC_VOLUME_DATA_OFFSET = 128KB

// Hidden volume header offset
pub const HIDDEN_VOLUME_HEADER_OFFSET: u64 = VOLUME_HEADER_SIZE as u64; // 64KB

// Salt
pub const SALT_SIZE: usize = 64; // PKCS5_SALT_SIZE

// Master key data
pub const MASTER_KEY_DATA_SIZE: usize = 256; // MASTER_KEYDATA_SIZE

// Encryption data unit
pub const ENCRYPTION_DATA_UNIT_SIZE: usize = 512; // ENCRYPTION_DATA_UNIT_SIZE
pub const BYTES_PER_XTS_BLOCK: usize = 16; // BYTES_PER_XTS_BLOCK
pub const BLOCKS_PER_XTS_DATA_UNIT: usize = ENCRYPTION_DATA_UNIT_SIZE / BYTES_PER_XTS_BLOCK; // 32

// Header field offsets (within the 512-byte header)
pub const HEADER_SALT_OFFSET: usize = 0;
pub const HEADER_ENCRYPTED_DATA_OFFSET: usize = SALT_SIZE; // 64
pub const HEADER_MASTER_KEY_DATA_OFFSET: usize = 256;
pub const HEADER_ENCRYPTED_DATA_SIZE: usize = VOLUME_HEADER_EFFECTIVE_SIZE - HEADER_ENCRYPTED_DATA_OFFSET; // 448

pub const OFFSET_MAGIC: usize = 64;
pub const OFFSET_VERSION: usize = 68;
pub const OFFSET_REQUIRED_VERSION: usize = 70;
pub const OFFSET_KEY_AREA_CRC: usize = 72;
pub const OFFSET_HIDDEN_VOLUME_SIZE: usize = 92;
pub const OFFSET_VOLUME_SIZE: usize = 100;
pub const OFFSET_ENCRYPTED_AREA_START: usize = 108;
pub const OFFSET_ENCRYPTED_AREA_LENGTH: usize = 116;
pub const OFFSET_FLAGS: usize = 124;
pub const OFFSET_SECTOR_SIZE: usize = 128;
pub const OFFSET_HEADER_CRC: usize = 252;

// Magic value "TRUE"
pub const MAGIC_TRUE: u32 = 0x5452_5545;

// Password limits
pub const MAX_PASSWORD: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_header_sizes() {
        assert_eq!(VOLUME_HEADER_SIZE, 65536);
        assert_eq!(VOLUME_HEADER_EFFECTIVE_SIZE, 512);
        assert_eq!(VOLUME_HEADER_GROUP_SIZE, 2 * VOLUME_HEADER_SIZE);
        assert_eq!(VOLUME_DATA_OFFSET, 131072); // 128KB
    }

    #[test]
    fn test_hidden_volume_header_offset() {
        assert_eq!(HIDDEN_VOLUME_HEADER_OFFSET, VOLUME_HEADER_SIZE as u64);
        assert_eq!(HIDDEN_VOLUME_HEADER_OFFSET, 65536);
    }

    #[test]
    fn test_encryption_data_unit_alignment() {
        // XTS blocks must divide evenly into data units
        assert_eq!(ENCRYPTION_DATA_UNIT_SIZE % BYTES_PER_XTS_BLOCK, 0);
        assert_eq!(BLOCKS_PER_XTS_DATA_UNIT, ENCRYPTION_DATA_UNIT_SIZE / BYTES_PER_XTS_BLOCK);
        assert_eq!(BLOCKS_PER_XTS_DATA_UNIT, 32);
    }

    #[test]
    fn test_header_field_offsets_within_bounds() {
        // All header field offsets must be within the effective header size
        assert!(OFFSET_MAGIC < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_VERSION < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_REQUIRED_VERSION < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_KEY_AREA_CRC < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_HIDDEN_VOLUME_SIZE < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_VOLUME_SIZE < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_ENCRYPTED_AREA_START < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_ENCRYPTED_AREA_LENGTH < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_FLAGS < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_SECTOR_SIZE < VOLUME_HEADER_EFFECTIVE_SIZE);
        assert!(OFFSET_HEADER_CRC < VOLUME_HEADER_EFFECTIVE_SIZE);
    }

    #[test]
    fn test_header_field_offsets_ordering() {
        // Fields should appear in ascending offset order
        assert!(OFFSET_MAGIC < OFFSET_VERSION);
        assert!(OFFSET_VERSION < OFFSET_REQUIRED_VERSION);
        assert!(OFFSET_REQUIRED_VERSION < OFFSET_KEY_AREA_CRC);
        assert!(OFFSET_KEY_AREA_CRC < OFFSET_HIDDEN_VOLUME_SIZE);
        assert!(OFFSET_HIDDEN_VOLUME_SIZE < OFFSET_VOLUME_SIZE);
        assert!(OFFSET_VOLUME_SIZE < OFFSET_ENCRYPTED_AREA_START);
        assert!(OFFSET_ENCRYPTED_AREA_START < OFFSET_ENCRYPTED_AREA_LENGTH);
        assert!(OFFSET_ENCRYPTED_AREA_LENGTH < OFFSET_FLAGS);
        assert!(OFFSET_FLAGS < OFFSET_SECTOR_SIZE);
    }

    #[test]
    fn test_encrypted_data_region() {
        // Encrypted data starts after salt and covers rest of header
        assert_eq!(HEADER_ENCRYPTED_DATA_OFFSET, SALT_SIZE);
        assert_eq!(
            HEADER_ENCRYPTED_DATA_SIZE,
            VOLUME_HEADER_EFFECTIVE_SIZE - HEADER_ENCRYPTED_DATA_OFFSET
        );
        assert_eq!(HEADER_ENCRYPTED_DATA_SIZE, 448);
    }

    #[test]
    fn test_master_key_data_fits_in_header() {
        // Master key data region must fit within the header
        assert!(HEADER_MASTER_KEY_DATA_OFFSET + MASTER_KEY_DATA_SIZE <= VOLUME_HEADER_EFFECTIVE_SIZE);
    }

    #[test]
    fn test_magic_value() {
        // "TRUE" in ASCII big-endian
        let bytes = MAGIC_TRUE.to_be_bytes();
        assert_eq!(&bytes, b"TRUE");
    }

    #[test]
    fn test_salt_and_password_sizes() {
        assert_eq!(SALT_SIZE, 64);
        assert_eq!(MAX_PASSWORD, 64);
        assert_eq!(MASTER_KEY_DATA_SIZE, 256);
    }

    #[test]
    fn test_header_crc_offset_after_all_fields() {
        // CRC should be after all other parsed header fields
        assert!(OFFSET_HEADER_CRC > OFFSET_SECTOR_SIZE);
        // CRC field (4 bytes) must fit before the master key area
        assert!(OFFSET_HEADER_CRC + 4 <= HEADER_MASTER_KEY_DATA_OFFSET);
    }
}
