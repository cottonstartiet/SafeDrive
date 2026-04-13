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
