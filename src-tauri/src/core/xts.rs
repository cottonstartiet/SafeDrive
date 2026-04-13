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
}
