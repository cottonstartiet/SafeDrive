/// CRC-32/ISO-HDLC matching TrueCrypt's implementation.
/// Polynomial: 0xEDB88320 (reflected 0x04C11DB7).

pub fn compute(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn compute_slice(data: &[u8], offset: usize, length: usize) -> u32 {
    compute(&data[offset..offset + length])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_values() {
        // CRC32 of empty input
        assert_eq!(compute(&[]), 0x0000_0000);
        // CRC32 of "123456789"
        assert_eq!(compute(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_slice() {
        let data = b"xx123456789yy";
        assert_eq!(compute_slice(data, 2, 9), 0xCBF4_3926);
    }

    #[test]
    fn test_single_byte() {
        // CRC32 of a single zero byte
        let result = compute(&[0x00]);
        assert_ne!(result, 0);
        // CRC32 of a single 0xFF byte
        let result2 = compute(&[0xFF]);
        assert_ne!(result2, 0);
        assert_ne!(result, result2);
    }

    #[test]
    fn test_different_inputs_produce_different_crcs() {
        let a = compute(b"hello");
        let b = compute(b"world");
        let c = compute(b"Hello"); // case-sensitive
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_deterministic() {
        // Same input always produces same output
        let data = b"test deterministic";
        assert_eq!(compute(data), compute(data));
    }

    #[test]
    fn test_slice_full_data() {
        let data = b"hello world";
        assert_eq!(compute_slice(data, 0, data.len()), compute(data));
    }

    #[test]
    fn test_slice_at_end() {
        let data = b"prefixDATA";
        let slice_crc = compute_slice(data, 6, 4);
        assert_eq!(slice_crc, compute(b"DATA"));
    }

    #[test]
    fn test_large_data() {
        // Verify CRC works for a 4KB+ block (common sector-aligned size)
        let data = vec![0xAB_u8; 4096];
        let crc = compute(&data);
        assert_ne!(crc, 0);
        // Same data should produce same CRC
        assert_eq!(crc, compute(&data));
    }

    #[test]
    fn test_all_zeros_vs_all_ones() {
        let zeros = vec![0x00_u8; 512];
        let ones = vec![0xFF_u8; 512];
        assert_ne!(compute(&zeros), compute(&ones));
    }

    #[test]
    fn test_known_ascii_strings() {
        // Well-known CRC32 test vectors
        assert_eq!(compute(b""), 0x0000_0000);
        assert_eq!(compute(b"123456789"), 0xCBF4_3926);
    }
}
