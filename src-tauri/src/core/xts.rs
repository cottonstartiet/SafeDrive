/// XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing) encrypt/decrypt.
/// Implements IEEE P1619 XTS generalized for any 128-bit block cipher.
/// Matches TrueCrypt's Xts.c implementation.

use crate::core::cipher::CipherEngine;
use crate::core::constants::{BYTES_PER_XTS_BLOCK, BLOCKS_PER_XTS_DATA_UNIT};

/// Multiply tweak by α (= x) in GF(2^128) with polynomial x^128+x^7+x^2+x+1.
/// Left-shift-by-1 with conditional XOR of 0x87 into byte[0]. Little-endian byte order.
#[inline]
fn gf_mul_128(tweak: &mut [u8; 16]) {
    let carry = (tweak[15] & 0x80) != 0;
    for i in (1..16).rev() {
        tweak[i] = (tweak[i] << 1) | (tweak[i - 1] >> 7);
    }
    tweak[0] <<= 1;
    if carry {
        tweak[0] ^= 0x87;
    }
}

/// Generates the initial tweak for a data unit.
fn make_tweak(data_unit_no: u64, secondary: &CipherEngine) -> [u8; 16] {
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&data_unit_no.to_le_bytes());
    secondary.encrypt_block(&mut tweak);
    tweak
}

/// Decrypts data in XTS mode using a single cipher.
pub fn decrypt_xts(
    data: &mut [u8],
    offset: usize,
    length: usize,
    data_unit_no: u64,
    start_block_no: usize,
    primary: &CipherEngine,
    secondary: &CipherEngine,
) {
    assert!(length % BYTES_PER_XTS_BLOCK == 0, "Length must be a multiple of 16 bytes");

    let mut blocks_remaining = length / BYTES_PER_XTS_BLOCK;
    let mut pos = offset;
    let mut current_unit = data_unit_no;
    let mut current_start_block = start_block_no;

    while blocks_remaining > 0 {
        let end_block = (current_start_block + blocks_remaining).min(BLOCKS_PER_XTS_DATA_UNIT);
        let mut tweak = make_tweak(current_unit, secondary);

        // Advance tweak to start_block_no
        for _ in 0..current_start_block {
            gf_mul_128(&mut tweak);
        }

        for _ in current_start_block..end_block {
            // XOR with tweak
            for j in 0..16 {
                data[pos + j] ^= tweak[j];
            }
            // Decrypt block
            primary.decrypt_block(&mut data[pos..]);
            // XOR with tweak
            for j in 0..16 {
                data[pos + j] ^= tweak[j];
            }
            gf_mul_128(&mut tweak);
            pos += 16;
        }

        blocks_remaining -= end_block - current_start_block;
        current_start_block = 0;
        current_unit += 1;
    }
}

/// Decrypts data using a cascade of ciphers in XTS mode.
/// Ciphers are applied in reverse order (last cipher first).
pub fn decrypt_xts_cascade(
    data: &mut [u8],
    offset: usize,
    length: usize,
    data_unit_no: u64,
    primary_engines: &[CipherEngine],
    secondary_engines: &[CipherEngine],
) {
    for i in (0..primary_engines.len()).rev() {
        decrypt_xts(data, offset, length, data_unit_no, 0, &primary_engines[i], &secondary_engines[i]);
    }
}

/// Encrypts data in XTS mode using a single cipher.
pub fn encrypt_xts(
    data: &mut [u8],
    offset: usize,
    length: usize,
    data_unit_no: u64,
    start_block_no: usize,
    primary: &CipherEngine,
    secondary: &CipherEngine,
) {
    assert!(length % BYTES_PER_XTS_BLOCK == 0, "Length must be a multiple of 16 bytes");

    let mut blocks_remaining = length / BYTES_PER_XTS_BLOCK;
    let mut pos = offset;
    let mut current_unit = data_unit_no;
    let mut current_start_block = start_block_no;

    while blocks_remaining > 0 {
        let end_block = (current_start_block + blocks_remaining).min(BLOCKS_PER_XTS_DATA_UNIT);
        let mut tweak = make_tweak(current_unit, secondary);

        for _ in 0..current_start_block {
            gf_mul_128(&mut tweak);
        }

        for _ in current_start_block..end_block {
            for j in 0..16 {
                data[pos + j] ^= tweak[j];
            }
            primary.encrypt_block(&mut data[pos..]);
            for j in 0..16 {
                data[pos + j] ^= tweak[j];
            }
            gf_mul_128(&mut tweak);
            pos += 16;
        }

        blocks_remaining -= end_block - current_start_block;
        current_start_block = 0;
        current_unit += 1;
    }
}

/// Encrypts data using a cascade of ciphers in XTS mode.
/// Ciphers are applied in forward order (first cipher first).
pub fn encrypt_xts_cascade(
    data: &mut [u8],
    offset: usize,
    length: usize,
    data_unit_no: u64,
    primary_engines: &[CipherEngine],
    secondary_engines: &[CipherEngine],
) {
    for i in 0..primary_engines.len() {
        encrypt_xts(data, offset, length, data_unit_no, 0, &primary_engines[i], &secondary_engines[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary_key = [0x44u8; 32];
        let secondary = CipherEngine::new("AES", &secondary_key);

        let original = [0xABu8; 512];
        let mut data = original;
        encrypt_xts(&mut data, 0, 512, 0, 0, &primary, &secondary);
        assert_ne!(data, original);
        decrypt_xts(&mut data, 0, 512, 0, 0, &primary, &secondary);
        assert_eq!(data, original);
    }

    #[test]
    fn test_cascade_roundtrip() {
        let key_material = [0x55u8; 256];
        let ea = &crate::core::cipher::EncryptionAlgorithm::ALL[3]; // Twofish-AES
        let (primary, secondary) = ea.create_engines(&key_material);

        let original = [0xCDu8; 512];
        let mut data = original;
        encrypt_xts_cascade(&mut data, 0, 512, 42, &primary, &secondary);
        assert_ne!(data, original);
        decrypt_xts_cascade(&mut data, 0, 512, 42, &primary, &secondary);
        assert_eq!(data, original);
    }

    #[test]
    fn test_gf_mul_128_known() {
        let mut tweak = [0u8; 16];
        tweak[0] = 1;
        gf_mul_128(&mut tweak);
        assert_eq!(tweak[0], 2);
        // With carry
        let mut tweak2 = [0u8; 16];
        tweak2[15] = 0x80;
        gf_mul_128(&mut tweak2);
        assert_eq!(tweak2[0], 0x87);
        assert_eq!(tweak2[15], 0x00);
    }

    #[test]
    fn test_serpent_xts_roundtrip() {
        let key = [0x11u8; 32];
        let primary = CipherEngine::new("Serpent", &key);
        let secondary_key = [0x22u8; 32];
        let secondary = CipherEngine::new("Serpent", &secondary_key);

        let original = [0xBBu8; 512];
        let mut data = original;
        encrypt_xts(&mut data, 0, 512, 0, 0, &primary, &secondary);
        assert_ne!(data, original);
        decrypt_xts(&mut data, 0, 512, 0, 0, &primary, &secondary);
        assert_eq!(data, original);
    }

    #[test]
    fn test_twofish_xts_roundtrip() {
        let key = [0x55u8; 32];
        let primary = CipherEngine::new("Twofish", &key);
        let secondary_key = [0x66u8; 32];
        let secondary = CipherEngine::new("Twofish", &secondary_key);

        let original = [0xCCu8; 512];
        let mut data = original;
        encrypt_xts(&mut data, 0, 512, 0, 0, &primary, &secondary);
        assert_ne!(data, original);
        decrypt_xts(&mut data, 0, 512, 0, 0, &primary, &secondary);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xts_with_nonzero_data_unit() {
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary_key = [0x44u8; 32];
        let secondary = CipherEngine::new("AES", &secondary_key);

        let original = [0xAAu8; 512];
        let mut data = original;
        // Use a non-zero data unit number
        encrypt_xts(&mut data, 0, 512, 100, 0, &primary, &secondary);
        assert_ne!(data, original);
        decrypt_xts(&mut data, 0, 512, 100, 0, &primary, &secondary);
        assert_eq!(data, original);
    }

    #[test]
    fn test_different_data_units_produce_different_ciphertext() {
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary_key = [0x44u8; 32];
        let secondary = CipherEngine::new("AES", &secondary_key);

        let original = [0xAAu8; 512];

        let mut data1 = original;
        let mut data2 = original;
        encrypt_xts(&mut data1, 0, 512, 0, 0, &primary, &secondary);
        encrypt_xts(&mut data2, 0, 512, 1, 0, &primary, &secondary);
        // Different data unit numbers should produce different ciphertext
        assert_ne!(data1, data2);
    }

    #[test]
    fn test_xts_with_start_block_nonzero() {
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary_key = [0x44u8; 32];
        let secondary = CipherEngine::new("AES", &secondary_key);

        // Encrypt/decrypt a single block (16 bytes) starting at block 5
        let original = [0xBBu8; 16];
        let mut data = original;
        encrypt_xts(&mut data, 0, 16, 0, 5, &primary, &secondary);
        assert_ne!(data, original);
        decrypt_xts(&mut data, 0, 16, 0, 5, &primary, &secondary);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xts_minimum_block() {
        // XTS minimum: one 16-byte block
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary_key = [0x44u8; 32];
        let secondary = CipherEngine::new("AES", &secondary_key);

        let original = [0xFFu8; 16];
        let mut data = original;
        encrypt_xts(&mut data, 0, 16, 0, 0, &primary, &secondary);
        assert_ne!(data, original);
        decrypt_xts(&mut data, 0, 16, 0, 0, &primary, &secondary);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xts_multi_sector() {
        // Test encrypting data spanning multiple data units (>512 bytes)
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary_key = [0x44u8; 32];
        let secondary = CipherEngine::new("AES", &secondary_key);

        let original = [0xDDu8; 1024]; // 2 sectors
        let mut data = original;
        encrypt_xts(&mut data, 0, 1024, 0, 0, &primary, &secondary);
        assert_ne!(data, original);
        decrypt_xts(&mut data, 0, 1024, 0, 0, &primary, &secondary);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xts_with_offset() {
        // Test with non-zero buffer offset
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary_key = [0x44u8; 32];
        let secondary = CipherEngine::new("AES", &secondary_key);

        let mut buffer = vec![0u8; 1024];
        let original_section = [0xEEu8; 512];
        buffer[512..1024].copy_from_slice(&original_section);

        encrypt_xts(&mut buffer, 512, 512, 0, 0, &primary, &secondary);
        // First 512 bytes should be untouched
        assert_eq!(&buffer[..512], &[0u8; 512]);
        // Encrypted section should differ
        assert_ne!(&buffer[512..1024], &original_section);

        decrypt_xts(&mut buffer, 512, 512, 0, 0, &primary, &secondary);
        assert_eq!(&buffer[512..1024], &original_section);
    }

    #[test]
    fn test_all_cascade_roundtrips() {
        let key_material = [0xAA_u8; 256];

        for ea in crate::core::cipher::EncryptionAlgorithm::ALL {
            let (primary, secondary) = ea.create_engines(&key_material);
            let original = [0x77u8; 512];
            let mut data = original;

            encrypt_xts_cascade(&mut data, 0, 512, 0, &primary, &secondary);
            assert_ne!(data, original, "Cascade {} encryption should change data", ea.name);
            decrypt_xts_cascade(&mut data, 0, 512, 0, &primary, &secondary);
            assert_eq!(data, original, "Cascade {} roundtrip failed", ea.name);
        }
    }

    #[test]
    fn test_gf_mul_128_no_carry() {
        // 2 * 2 = 4 in GF(2^128)
        let mut tweak = [0u8; 16];
        tweak[0] = 2;
        gf_mul_128(&mut tweak);
        assert_eq!(tweak[0], 4);
    }

    #[test]
    fn test_gf_mul_128_sequential() {
        // Verify sequential multiplications are consistent
        let mut tweak = [0u8; 16];
        tweak[0] = 1;

        // α^1
        gf_mul_128(&mut tweak);
        assert_eq!(tweak[0], 2);

        // α^2
        gf_mul_128(&mut tweak);
        assert_eq!(tweak[0], 4);

        // α^3
        gf_mul_128(&mut tweak);
        assert_eq!(tweak[0], 8);
    }

    #[test]
    #[should_panic(expected = "Length must be a multiple of 16 bytes")]
    fn test_encrypt_xts_non_aligned_length() {
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary = CipherEngine::new("AES", &key);
        let mut data = [0u8; 17];
        encrypt_xts(&mut data, 0, 17, 0, 0, &primary, &secondary);
    }

    #[test]
    #[should_panic(expected = "Length must be a multiple of 16 bytes")]
    fn test_decrypt_xts_non_aligned_length() {
        let key = [0x33u8; 32];
        let primary = CipherEngine::new("AES", &key);
        let secondary = CipherEngine::new("AES", &key);
        let mut data = [0u8; 15];
        decrypt_xts(&mut data, 0, 15, 0, 0, &primary, &secondary);
    }
}
