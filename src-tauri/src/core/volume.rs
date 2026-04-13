/// High-level API for opening TrueCrypt volumes and accessing files.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use crate::core::constants::*;
use crate::core::decrypted_stream::DecryptedStream;
use crate::core::volume_header::VolumeHeader;

pub struct TrueCryptVolume {
    header: VolumeHeader,
    decrypted_stream: DecryptedStream<File>,
}

/// Error type for volume operations.
#[derive(Debug)]
pub enum VolumeError {
    Io(io::Error),
    InvalidPassword,
    UnsupportedFormat(String),
}

impl std::fmt::Display for VolumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeError::Io(e) => write!(f, "I/O error: {}", e),
            VolumeError::InvalidPassword => write!(f, "Wrong password or not a valid TrueCrypt volume"),
            VolumeError::UnsupportedFormat(msg) => write!(f, "Unsupported format: {}", msg),
        }
    }
}

impl std::error::Error for VolumeError {}

impl From<io::Error> for VolumeError {
    fn from(e: io::Error) -> Self {
        VolumeError::Io(e)
    }
}

impl TrueCryptVolume {
    /// Opens a TrueCrypt volume file with the given password.
    /// Tries primary header, hidden volume header, then backup header.
    pub fn open(path: &Path, password: &str, writable: bool) -> Result<Self, VolumeError> {
        let password_bytes = password.as_bytes();

        let mut file = if writable {
            OpenOptions::new().read(true).write(true).open(path)?
        } else {
            File::open(path)?
        };

        let file_len = file.seek(SeekFrom::End(0))?;

        // Read first 512 bytes (primary header)
        let mut header_bytes = [0u8; VOLUME_HEADER_EFFECTIVE_SIZE];
        file.seek(SeekFrom::Start(0))?;
        read_full(&mut file, &mut header_bytes)?;

        // Try primary header
        let mut header = VolumeHeader::try_decrypt(&header_bytes, password_bytes);

        // If primary fails, try hidden volume header at offset 64KB
        if header.is_none() {
            file.seek(SeekFrom::Start(HIDDEN_VOLUME_HEADER_OFFSET))?;
            read_full(&mut file, &mut header_bytes)?;
            header = VolumeHeader::try_decrypt(&header_bytes, password_bytes);
        }

        // If still none, try backup header at end of volume
        if header.is_none() {
            let backup_offset = file_len.checked_sub(VOLUME_HEADER_GROUP_SIZE as u64);
            if let Some(offset) = backup_offset {
                file.seek(SeekFrom::Start(offset))?;
                read_full(&mut file, &mut header_bytes)?;
                header = VolumeHeader::try_decrypt(&header_bytes, password_bytes);
            }
        }

        let header = header.ok_or(VolumeError::InvalidPassword)?;
        let decrypted_stream = DecryptedStream::new(file, &header, writable)?;

        Ok(TrueCryptVolume {
            header,
            decrypted_stream,
        })
    }

    pub fn header(&self) -> &VolumeHeader {
        &self.header
    }

    pub fn decrypted_stream(&mut self) -> &mut DecryptedStream<File> {
        &mut self.decrypted_stream
    }
}

fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected end of file")),
            n => total += n,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_volume_error_display_io() {
        let err = VolumeError::Io(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        let msg = format!("{}", err);
        assert!(msg.contains("I/O error"));
        assert!(msg.contains("file not found"));
    }

    #[test]
    fn test_volume_error_display_invalid_password() {
        let err = VolumeError::InvalidPassword;
        let msg = format!("{}", err);
        assert!(msg.contains("Wrong password"));
    }

    #[test]
    fn test_volume_error_display_unsupported() {
        let err = VolumeError::UnsupportedFormat("test format".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Unsupported format"));
        assert!(msg.contains("test format"));
    }

    #[test]
    fn test_volume_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let vol_err: VolumeError = io_err.into();
        match vol_err {
            VolumeError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            _ => panic!("Expected VolumeError::Io"),
        }
    }

    #[test]
    fn test_volume_error_is_std_error() {
        // Ensure VolumeError implements std::error::Error
        let err: Box<dyn std::error::Error> = Box::new(VolumeError::InvalidPassword);
        assert!(err.to_string().contains("Wrong password"));
    }

    #[test]
    fn test_open_nonexistent_file() {
        let result = TrueCryptVolume::open(
            Path::new("/tmp/nonexistent_volume_file_12345.tc"),
            "password",
            false,
        );
        assert!(result.is_err());
        let err = result.err().unwrap();
        match &err {
            VolumeError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            _ => panic!("Expected Io error, got: {}", err),
        }
    }

    #[test]
    fn test_open_invalid_volume() {
        // Create a temp file with random data (not a valid TC volume)
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_invalid_volume.tc");
        let data = vec![0xAA_u8; 1024 * 1024]; // 1MB of garbage data
        std::fs::write(&path, &data).unwrap();

        let result = TrueCryptVolume::open(&path, "password", false);
        assert!(result.is_err());
        let err = result.err().unwrap();
        match &err {
            VolumeError::InvalidPassword => {} // Expected
            _ => panic!("Expected InvalidPassword, got: {}", err),
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_open_empty_file() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_empty_volume.tc");
        std::fs::write(&path, &[]).unwrap();

        let result = TrueCryptVolume::open(&path, "password", false);
        // Empty file should fail (can't read header)
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_open_too_small_file() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_small_volume.tc");
        std::fs::write(&path, &[0u8; 100]).unwrap();

        let result = TrueCryptVolume::open(&path, "password", false);
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_read_full_helper() {
        let data = vec![1, 2, 3, 4, 5];
        let mut cursor = Cursor::new(data.clone());
        let mut buf = vec![0u8; 5];
        read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_read_full_short_input() {
        let data = vec![1, 2, 3];
        let mut cursor = Cursor::new(data);
        let mut buf = vec![0u8; 10];
        let result = read_full(&mut cursor, &mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_read_full_exact() {
        let data = vec![0xAA; 512];
        let mut cursor = Cursor::new(data.clone());
        let mut buf = vec![0u8; 512];
        read_full(&mut cursor, &mut buf).unwrap();
        assert_eq!(buf, data);
    }
}
