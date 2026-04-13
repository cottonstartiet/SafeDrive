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
}
