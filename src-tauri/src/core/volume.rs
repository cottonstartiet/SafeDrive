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
