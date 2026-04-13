/// A stream that decrypts/encrypts TrueCrypt volume data on-the-fly.
/// Wraps the raw volume file and provides transparent XTS processing.
/// Position 0 = first byte of the filesystem (data area).

use std::io::{self, Read, Seek, SeekFrom, Write};
use crate::core::cipher::CipherEngine;
use crate::core::constants::*;
use crate::core::volume_header::VolumeHeader;
use crate::core::xts;

pub struct DecryptedStream<S: Read + Seek + Write> {
    base_stream: S,
    data_area_offset: u64,
    data_area_length: u64,
    primary_engines: Vec<CipherEngine>,
    secondary_engines: Vec<CipherEngine>,
    position: u64,
    writable: bool,
}

impl<S: Read + Seek + Write> DecryptedStream<S> {
    pub fn new(mut base_stream: S, header: &VolumeHeader, writable: bool) -> io::Result<Self> {
        let stream_len = base_stream.seek(SeekFrom::End(0))?;

        let data_area_offset = if header.is_hidden_volume() {
            stream_len - header.hidden_volume_size - VOLUME_HEADER_GROUP_SIZE as u64
        } else if header.encrypted_area_start > 0 {
            header.encrypted_area_start
        } else {
            VOLUME_DATA_OFFSET
        };

        let data_area_length = if header.encrypted_area_length > 0 {
            header.encrypted_area_length
        } else if header.volume_size > 0 {
            header.volume_size
        } else {
            stream_len - data_area_offset
        };

        let ea = header.encryption_algorithm;
        let key_size = ea.key_size();
        let mut primary_engines = Vec::with_capacity(ea.cipher_names.len());
        let mut secondary_engines = Vec::with_capacity(ea.cipher_names.len());

        for (i, &cipher_name) in ea.cipher_names.iter().enumerate() {
            let mut pk = [0u8; 32];
            let mut sk = [0u8; 32];
            pk.copy_from_slice(&header.master_key_data[i * 32..(i + 1) * 32]);
            sk.copy_from_slice(&header.master_key_data[key_size + i * 32..key_size + (i + 1) * 32]);
            primary_engines.push(CipherEngine::new(cipher_name, &pk));
            secondary_engines.push(CipherEngine::new(cipher_name, &sk));
        }

        Ok(DecryptedStream {
            base_stream,
            data_area_offset,
            data_area_length,
            primary_engines,
            secondary_engines,
            position: 0,
            writable,
        })
    }

    pub fn data_area_offset(&self) -> u64 {
        self.data_area_offset
    }

    pub fn data_area_length(&self) -> u64 {
        self.data_area_length
    }
}

impl<S: Read + Seek + Write> Read for DecryptedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.data_area_length {
            return Ok(0);
        }

        let available = self.data_area_length - self.position;
        let mut count = buf.len().min(available as usize);
        if count == 0 {
            return Ok(0);
        }

        let mut total_read = 0;
        let mut buf_offset = 0;

        while count > 0 {
            let sector_index = self.position / ENCRYPTION_DATA_UNIT_SIZE as u64;
            let offset_in_sector = (self.position % ENCRYPTION_DATA_UNIT_SIZE as u64) as usize;

            let mut sector = [0u8; ENCRYPTION_DATA_UNIT_SIZE];
            let file_offset = self.data_area_offset + sector_index * ENCRYPTION_DATA_UNIT_SIZE as u64;

            self.base_stream.seek(SeekFrom::Start(file_offset))?;
            let bytes_read = read_full(&mut self.base_stream, &mut sector)?;
            if bytes_read == 0 {
                break;
            }

            // Data unit number from ABSOLUTE file offset (matches TrueCrypt behavior)
            let data_unit_no = file_offset / ENCRYPTION_DATA_UNIT_SIZE as u64;
            xts::decrypt_xts_cascade(
                &mut sector, 0, ENCRYPTION_DATA_UNIT_SIZE, data_unit_no,
                &self.primary_engines, &self.secondary_engines,
            );

            let to_copy = count.min(ENCRYPTION_DATA_UNIT_SIZE - offset_in_sector)
                .min(bytes_read - offset_in_sector);
            if to_copy == 0 {
                break;
            }

            buf[buf_offset..buf_offset + to_copy]
                .copy_from_slice(&sector[offset_in_sector..offset_in_sector + to_copy]);

            self.position += to_copy as u64;
            buf_offset += to_copy;
            total_read += to_copy;
            count -= to_copy;
        }

        Ok(total_read)
    }
}

impl<S: Read + Seek + Write> Seek for DecryptedStream<S> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    self.position + offset as u64
                } else {
                    self.position.checked_sub((-offset) as u64)
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Seek before start"))?
                }
            }
            SeekFrom::End(offset) => {
                if offset >= 0 {
                    self.data_area_length + offset as u64
                } else {
                    self.data_area_length.checked_sub((-offset) as u64)
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Seek before start"))?
                }
            }
        };
        Ok(self.position)
    }
}

impl<S: Read + Seek + Write> Write for DecryptedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Stream is read-only"));
        }
        if self.position + buf.len() as u64 > self.data_area_length {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Write would exceed data area"));
        }

        let mut written = 0;
        let mut remaining = buf.len();

        while remaining > 0 {
            let sector_index = self.position / ENCRYPTION_DATA_UNIT_SIZE as u64;
            let offset_in_sector = (self.position % ENCRYPTION_DATA_UNIT_SIZE as u64) as usize;
            let file_offset = self.data_area_offset + sector_index * ENCRYPTION_DATA_UNIT_SIZE as u64;

            let mut sector = [0u8; ENCRYPTION_DATA_UNIT_SIZE];

            // Read-modify-write for partial sectors
            if offset_in_sector != 0 || remaining < ENCRYPTION_DATA_UNIT_SIZE {
                self.base_stream.seek(SeekFrom::Start(file_offset))?;
                read_full(&mut self.base_stream, &mut sector)?;
                let data_unit_no = file_offset / ENCRYPTION_DATA_UNIT_SIZE as u64;
                xts::decrypt_xts_cascade(
                    &mut sector, 0, ENCRYPTION_DATA_UNIT_SIZE, data_unit_no,
                    &self.primary_engines, &self.secondary_engines,
                );
            }

            let to_copy = remaining.min(ENCRYPTION_DATA_UNIT_SIZE - offset_in_sector);
            sector[offset_in_sector..offset_in_sector + to_copy]
                .copy_from_slice(&buf[written..written + to_copy]);

            // Encrypt and write back
            let data_unit_no = file_offset / ENCRYPTION_DATA_UNIT_SIZE as u64;
            xts::encrypt_xts_cascade(
                &mut sector, 0, ENCRYPTION_DATA_UNIT_SIZE, data_unit_no,
                &self.primary_engines, &self.secondary_engines,
            );

            self.base_stream.seek(SeekFrom::Start(file_offset))?;
            self.base_stream.write_all(&sector)?;

            self.position += to_copy as u64;
            written += to_copy;
            remaining -= to_copy;
        }

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.base_stream.flush()
    }
}

fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Creates a test VolumeHeader and matching encrypted stream data for testing.
    /// Uses AES encryption with known key material.
    fn make_test_volume(data_size: usize, writable: bool) -> (DecryptedStream<Cursor<Vec<u8>>>, Vec<u8>) {
        use crate::core::cipher::EncryptionAlgorithm;
        use crate::core::key_derivation::Prf;

        let ea = &EncryptionAlgorithm::ALL[0]; // AES
        let master_key = [0x42u8; MASTER_KEY_DATA_SIZE];

        let header = crate::core::volume_header::VolumeHeader {
            header_version: 5,
            required_program_version: 0x0700,
            hidden_volume_size: 0,
            volume_size: data_size as u64,
            encrypted_area_start: 0,
            encrypted_area_length: data_size as u64,
            flags: 0,
            sector_size: 512,
            master_key_data: master_key,
            salt: [0u8; SALT_SIZE],
            encryption_algorithm: ea,
            prf: Prf::Sha512,
        };

        // The data_area_offset will be VOLUME_DATA_OFFSET (128KB) since it's not hidden
        // and encrypted_area_start is 0
        let total_size = VOLUME_DATA_OFFSET as usize + data_size;
        let mut raw_data = vec![0u8; total_size];

        // Fill the data area with known plaintext, encrypt it sector by sector
        let plaintext = (0..data_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();

        // Create engines from master key
        let key_size = ea.key_size();
        let mut primary_engines = Vec::new();
        let mut secondary_engines = Vec::new();
        for (i, &cipher_name) in ea.cipher_names.iter().enumerate() {
            let mut pk = [0u8; 32];
            let mut sk = [0u8; 32];
            pk.copy_from_slice(&master_key[i * 32..(i + 1) * 32]);
            sk.copy_from_slice(&master_key[key_size + i * 32..key_size + (i + 1) * 32]);
            primary_engines.push(crate::core::cipher::CipherEngine::new(cipher_name, &pk));
            secondary_engines.push(crate::core::cipher::CipherEngine::new(cipher_name, &sk));
        }

        // Encrypt each sector and write to raw_data
        let data_offset = VOLUME_DATA_OFFSET as usize;
        for sector_idx in 0..(data_size / ENCRYPTION_DATA_UNIT_SIZE) {
            let start = sector_idx * ENCRYPTION_DATA_UNIT_SIZE;
            let file_offset = data_offset + start;
            let data_unit_no = file_offset as u64 / ENCRYPTION_DATA_UNIT_SIZE as u64;

            let mut sector = [0u8; ENCRYPTION_DATA_UNIT_SIZE];
            sector.copy_from_slice(&plaintext[start..start + ENCRYPTION_DATA_UNIT_SIZE]);

            crate::core::xts::encrypt_xts_cascade(
                &mut sector, 0, ENCRYPTION_DATA_UNIT_SIZE, data_unit_no,
                &primary_engines, &secondary_engines,
            );

            raw_data[file_offset..file_offset + ENCRYPTION_DATA_UNIT_SIZE]
                .copy_from_slice(&sector);
        }

        let cursor = Cursor::new(raw_data);
        let stream = DecryptedStream::new(cursor, &header, writable).unwrap();

        (stream, plaintext)
    }

    #[test]
    fn test_data_area_offset_standard_volume() {
        let (stream, _) = make_test_volume(512, false);
        assert_eq!(stream.data_area_offset(), VOLUME_DATA_OFFSET);
    }

    #[test]
    fn test_data_area_length() {
        let data_size = 1024;
        let (stream, _) = make_test_volume(data_size, false);
        assert_eq!(stream.data_area_length(), data_size as u64);
    }

    #[test]
    fn test_read_single_sector() {
        let (mut stream, plaintext) = make_test_volume(512, false);
        let mut buf = vec![0u8; 512];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 512);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn test_read_multiple_sectors() {
        let (mut stream, plaintext) = make_test_volume(1024, false);
        let mut buf = vec![0u8; 1024];
        let mut total = 0;
        while total < 1024 {
            let n = stream.read(&mut buf[total..]).unwrap();
            if n == 0 { break; }
            total += n;
        }
        assert_eq!(total, 1024);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn test_read_past_end_returns_zero() {
        let (mut stream, _) = make_test_volume(512, false);
        // Read all data
        let mut buf = vec![0u8; 512];
        stream.read(&mut buf).unwrap();
        // Read past end should return 0
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_seek_start() {
        let (mut stream, _) = make_test_volume(512, false);
        let pos = stream.seek(SeekFrom::Start(100)).unwrap();
        assert_eq!(pos, 100);
    }

    #[test]
    fn test_seek_current_forward() {
        let (mut stream, _) = make_test_volume(512, false);
        stream.seek(SeekFrom::Start(50)).unwrap();
        let pos = stream.seek(SeekFrom::Current(50)).unwrap();
        assert_eq!(pos, 100);
    }

    #[test]
    fn test_seek_current_backward() {
        let (mut stream, _) = make_test_volume(512, false);
        stream.seek(SeekFrom::Start(100)).unwrap();
        let pos = stream.seek(SeekFrom::Current(-50)).unwrap();
        assert_eq!(pos, 50);
    }

    #[test]
    fn test_seek_end() {
        let (mut stream, _) = make_test_volume(512, false);
        let pos = stream.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(pos, 512);
    }

    #[test]
    fn test_seek_end_negative() {
        let (mut stream, _) = make_test_volume(512, false);
        let pos = stream.seek(SeekFrom::End(-100)).unwrap();
        assert_eq!(pos, 412);
    }

    #[test]
    fn test_seek_before_start_errors() {
        let (mut stream, _) = make_test_volume(512, false);
        let result = stream.seek(SeekFrom::Current(-1));
        assert!(result.is_err());
    }

    #[test]
    fn test_seek_then_read() {
        let (mut stream, plaintext) = make_test_volume(1024, false);
        // Seek to sector boundary and read
        stream.seek(SeekFrom::Start(512)).unwrap();
        let mut buf = vec![0u8; 512];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 512);
        assert_eq!(buf, &plaintext[512..1024]);
    }

    #[test]
    fn test_read_partial_sector() {
        let (mut stream, plaintext) = make_test_volume(512, false);
        // Read only 100 bytes from a 512-byte sector
        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 100);
        assert_eq!(buf, &plaintext[..100]);
    }

    #[test]
    fn test_write_readonly_errors() {
        let (mut stream, _) = make_test_volume(512, false);
        let buf = [0u8; 16];
        let result = stream.write(&buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_write_then_read_roundtrip() {
        let data_size = 512;
        let (mut stream, _) = make_test_volume(data_size, true);

        // Write new data
        let write_data = [0xEE_u8; 512];
        stream.seek(SeekFrom::Start(0)).unwrap();
        let n = stream.write(&write_data).unwrap();
        assert_eq!(n, 512);

        // Read it back
        stream.seek(SeekFrom::Start(0)).unwrap();
        let mut read_buf = vec![0u8; 512];
        let n = stream.read(&mut read_buf).unwrap();
        assert_eq!(n, 512);
        assert_eq!(read_buf, write_data);
    }

    #[test]
    fn test_write_exceeds_data_area() {
        let (mut stream, _) = make_test_volume(512, true);
        // Try to write more than the data area
        let big_buf = [0u8; 1024];
        let result = stream.write(&big_buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_flush() {
        let (mut stream, _) = make_test_volume(512, true);
        assert!(stream.flush().is_ok());
    }

    #[test]
    fn test_read_full_helper() {
        let data = vec![1, 2, 3, 4, 5];
        let mut cursor = Cursor::new(data.clone());
        let mut buf = vec![0u8; 5];
        let n = read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, data);
    }

    #[test]
    fn test_read_full_short_read() {
        let data = vec![1, 2, 3];
        let mut cursor = Cursor::new(data);
        let mut buf = vec![0u8; 10];
        let n = read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn test_hidden_volume_data_area_offset() {
        use crate::core::cipher::EncryptionAlgorithm;
        use crate::core::key_derivation::Prf;

        let hidden_size = 1024u64;
        let stream_len = 1024 * 1024u64; // 1MB total

        let header = crate::core::volume_header::VolumeHeader {
            header_version: 5,
            required_program_version: 0x0700,
            hidden_volume_size: hidden_size,
            volume_size: hidden_size,
            encrypted_area_start: 0,
            encrypted_area_length: hidden_size,
            flags: 0,
            sector_size: 512,
            master_key_data: [0u8; MASTER_KEY_DATA_SIZE],
            salt: [0u8; SALT_SIZE],
            encryption_algorithm: &EncryptionAlgorithm::ALL[0],
            prf: Prf::Sha512,
        };

        let raw = vec![0u8; stream_len as usize];
        let cursor = Cursor::new(raw);
        let stream = DecryptedStream::new(cursor, &header, false).unwrap();

        // Hidden volume offset: stream_len - hidden_volume_size - VOLUME_HEADER_GROUP_SIZE
        let expected = stream_len - hidden_size - VOLUME_HEADER_GROUP_SIZE as u64;
        assert_eq!(stream.data_area_offset(), expected);
    }
}
