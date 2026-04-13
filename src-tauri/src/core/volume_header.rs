/// TrueCrypt volume header parsing and decryption.
/// Tries all PRF × cipher combinations to find the correct one.

use crate::core::cipher::EncryptionAlgorithm;
use crate::core::constants::*;
use crate::core::crc32;
use crate::core::key_derivation::{self, Prf};
use crate::core::xts;
use serde::Serialize;

/// Parsed and validated TrueCrypt volume header.
#[derive(Clone)]
pub struct VolumeHeader {
    pub header_version: u16,
    pub required_program_version: u16,
    pub hidden_volume_size: u64,
    pub volume_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub flags: u32,
    pub sector_size: u32,
    pub master_key_data: [u8; MASTER_KEY_DATA_SIZE],
    pub salt: [u8; SALT_SIZE],
    pub encryption_algorithm: &'static EncryptionAlgorithm,
    pub prf: Prf,
}

/// Serializable volume info for the frontend.
#[derive(Serialize, Clone)]
pub struct VolumeInfo {
    pub encryption: String,
    pub hash: String,
    pub header_version: u16,
    pub volume_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub sector_size: u32,
    pub is_hidden: bool,
}

impl VolumeHeader {
    pub fn is_hidden_volume(&self) -> bool {
        self.hidden_volume_size != 0
    }

    pub fn to_info(&self) -> VolumeInfo {
        VolumeInfo {
            encryption: self.encryption_algorithm.name.to_string(),
            hash: self.prf.name().to_string(),
            header_version: self.header_version,
            volume_size: self.volume_size,
            encrypted_area_start: self.encrypted_area_start,
            encrypted_area_length: self.encrypted_area_length,
            sector_size: self.sector_size,
            is_hidden: self.is_hidden_volume(),
        }
    }

    /// Attempts to decrypt and validate a volume header.
    /// Tries all PRF × cipher combinations. Returns None if password is wrong.
    pub fn try_decrypt(header_bytes: &[u8], password: &[u8]) -> Option<VolumeHeader> {
        if header_bytes.len() < VOLUME_HEADER_EFFECTIVE_SIZE {
            return None;
        }

        // Extract salt (unencrypted, first 64 bytes)
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&header_bytes[HEADER_SALT_OFFSET..HEADER_SALT_OFFSET + SALT_SIZE]);

        for &prf in Prf::ALL {
            let derived_key = key_derivation::derive_key(password, &salt, prf, false);

            for ea in EncryptionAlgorithm::ALL {
                // Need 2× key size (primary + secondary XTS keys)
                if ea.key_size() * 2 > derived_key.len() {
                    continue;
                }

                let (primary_engines, secondary_engines) = ea.create_engines(&derived_key);

                // Copy header for decryption attempt
                let mut header = [0u8; VOLUME_HEADER_EFFECTIVE_SIZE];
                header.copy_from_slice(&header_bytes[..VOLUME_HEADER_EFFECTIVE_SIZE]);

                // Decrypt bytes 64..511 using XTS with data unit #0
                xts::decrypt_xts_cascade(
                    &mut header,
                    HEADER_ENCRYPTED_DATA_OFFSET,
                    HEADER_ENCRYPTED_DATA_SIZE,
                    0,
                    &primary_engines,
                    &secondary_engines,
                );

                // Check magic "TRUE" at offset 64
                let magic = read_be_u32(&header, OFFSET_MAGIC);
                if magic != MAGIC_TRUE {
                    continue;
                }

                // Validate header CRC (CRC32 of bytes 64..252 vs value at offset 252)
                let header_crc = read_be_u32(&header, OFFSET_HEADER_CRC);
                let computed_header_crc = crc32::compute_slice(
                    &header,
                    OFFSET_MAGIC,
                    OFFSET_HEADER_CRC - OFFSET_MAGIC,
                );
                if header_crc != computed_header_crc {
                    continue;
                }

                // Validate key area CRC (CRC32 of bytes 256..512 vs value at offset 72)
                let key_area_crc = read_be_u32(&header, OFFSET_KEY_AREA_CRC);
                let computed_key_area_crc = crc32::compute_slice(
                    &header,
                    HEADER_MASTER_KEY_DATA_OFFSET,
                    MASTER_KEY_DATA_SIZE,
                );
                if key_area_crc != computed_key_area_crc {
                    continue;
                }

                // Success! Parse header fields
                let version = read_be_u16(&header, OFFSET_VERSION);
                let sector_size = if version >= 5 {
                    read_be_u32(&header, OFFSET_SECTOR_SIZE)
                } else {
                    512
                };

                let mut master_key_data = [0u8; MASTER_KEY_DATA_SIZE];
                master_key_data.copy_from_slice(
                    &header[HEADER_MASTER_KEY_DATA_OFFSET
                        ..HEADER_MASTER_KEY_DATA_OFFSET + MASTER_KEY_DATA_SIZE],
                );

                return Some(VolumeHeader {
                    header_version: version,
                    required_program_version: read_be_u16(&header, OFFSET_REQUIRED_VERSION),
                    hidden_volume_size: read_be_u64(&header, OFFSET_HIDDEN_VOLUME_SIZE),
                    volume_size: read_be_u64(&header, OFFSET_VOLUME_SIZE),
                    encrypted_area_start: read_be_u64(&header, OFFSET_ENCRYPTED_AREA_START),
                    encrypted_area_length: read_be_u64(&header, OFFSET_ENCRYPTED_AREA_LENGTH),
                    flags: read_be_u32(&header, OFFSET_FLAGS),
                    sector_size,
                    master_key_data,
                    salt,
                    encryption_algorithm: ea,
                    prf,
                });
            }
        }

        None
    }
}

fn read_be_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn read_be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_be_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}
