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
