/// Filesystem detection, file listing, and extraction for FAT and NTFS volumes.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum FsType {
    Fat,
    Ntfs,
    Unknown,
}

/// Detect filesystem type from the first sector of the decrypted stream.
pub fn detect_filesystem<S: Read + Seek>(stream: &mut S) -> io::Result<FsType> {
    stream.seek(SeekFrom::Start(0))?;
    let mut boot = [0u8; 512];
    stream.read_exact(&mut boot)?;
    stream.seek(SeekFrom::Start(0))?;

    let oem_id = std::str::from_utf8(&boot[3..11])
        .unwrap_or("")
        .trim_matches(|c: char| c == '\0' || c == ' ');

    if oem_id.eq_ignore_ascii_case("NTFS") {
        Ok(FsType::Ntfs)
    } else if boot[510] == 0x55 && boot[511] == 0xAA {
        Ok(FsType::Fat)
    } else {
        Ok(FsType::Unknown)
    }
}

/// List all files in the volume, auto-detecting filesystem.
pub fn list_files<S: Read + Write + Seek>(
    stream: &mut S,
) -> io::Result<Vec<FileEntry>> {
    let fs_type = detect_filesystem(stream)?;
    match fs_type {
        FsType::Fat => list_files_fat(stream),
        FsType::Ntfs => list_files_ntfs(stream),
        FsType::Unknown => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unsupported or unrecognized filesystem",
        )),
    }
}

/// Extract all files to `dest`, auto-detecting filesystem.
/// Returns the number of files extracted.
pub fn extract_all<S: Read + Write + Seek>(
    stream: &mut S,
    dest: &Path,
    progress: &dyn Fn(f64),
) -> io::Result<usize> {
    let fs_type = detect_filesystem(stream)?;
    match fs_type {
        FsType::Fat => extract_all_fat(stream, dest, progress),
        FsType::Ntfs => extract_all_ntfs(stream, dest, progress),
        FsType::Unknown => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unsupported or unrecognized filesystem",
        )),
    }
}

/// Extract a single file from the volume to a local path.
pub fn extract_file<S: Read + Write + Seek>(
    stream: &mut S,
    volume_path: &str,
    dest: &Path,
) -> io::Result<()> {
    let fs_type = detect_filesystem(stream)?;
    match fs_type {
        FsType::Fat => extract_file_fat(stream, volume_path, dest),
        FsType::Ntfs => extract_file_ntfs(stream, volume_path, dest),
        FsType::Unknown => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unsupported or unrecognized filesystem",
        )),
    }
}

// ---------------------------------------------------------------------------
// FAT implementation
// ---------------------------------------------------------------------------

fn list_files_fat<S: Read + Write + Seek>(stream: &mut S) -> io::Result<Vec<FileEntry>> {
    stream.seek(SeekFrom::Start(0))?;
    let fs = fatfs::FileSystem::new(stream, fatfs::FsOptions::new())?;
    let root = fs.root_dir();
    let mut entries = Vec::new();
    collect_fat_entries(&root, "\\", &mut entries)?;
    Ok(entries)
}

fn collect_fat_entries<'a, IO: fatfs::ReadWriteSeek>(
    dir: &fatfs::Dir<'a, IO>,
    current_path: &str,
    entries: &mut Vec<FileEntry>,
) -> io::Result<()> {
    for item in dir.iter() {
        let item = item?;
        let name = item.file_name();
        if name == "." || name == ".." {
            continue;
        }

        let full_path = if current_path == "\\" {
            format!("\\{}", name)
        } else {
            format!("{}\\{}", current_path, name)
        };

        if item.is_dir() {
            entries.push(FileEntry {
                name: name.clone(),
                path: full_path.clone(),
                size: 0,
                is_dir: true,
            });
            let sub_dir = dir.open_dir(&name)?;
            collect_fat_entries(&sub_dir, &full_path, entries)?;
        } else {
            entries.push(FileEntry {
                name,
                path: full_path,
                size: item.len(),
                is_dir: false,
            });
        }
    }
    Ok(())
}

fn extract_all_fat<S: Read + Write + Seek>(
    stream: &mut S,
    dest: &Path,
    progress: &dyn Fn(f64),
) -> io::Result<usize> {
    stream.seek(SeekFrom::Start(0))?;
    let file_list = list_files_fat(stream)?;
    let total_files = file_list.iter().filter(|f| !f.is_dir).count();

    stream.seek(SeekFrom::Start(0))?;
    let fs = fatfs::FileSystem::new(stream, fatfs::FsOptions::new())?;
    let root = fs.root_dir();

    let mut count = 0;
    extract_fat_dir_recursive(&root, dest, &mut count, total_files, progress)?;
    Ok(count)
}

fn extract_fat_dir_recursive<'a, IO: fatfs::ReadWriteSeek>(
    dir: &fatfs::Dir<'a, IO>,
    dest: &Path,
    count: &mut usize,
    total: usize,
    progress: &dyn Fn(f64),
) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;

    for item in dir.iter() {
        let item = item?;
        let name = item.file_name();
        if name == "." || name == ".." {
            continue;
        }

        if item.is_dir() {
            let sub_dest = dest.join(&name);
            let sub_dir = dir.open_dir(&name)?;
            extract_fat_dir_recursive(&sub_dir, &sub_dest, count, total, progress)?;
        } else {
            let file_dest = dest.join(&name);
            let mut src = dir.open_file(&name)?;
            let mut dst = std::fs::File::create(&file_dest)?;
            io::copy(&mut src, &mut dst)?;
            *count += 1;
            if total > 0 {
                progress(*count as f64 / total as f64);
            }
        }
    }
    Ok(())
}

fn extract_file_fat<S: Read + Write + Seek>(
    stream: &mut S,
    volume_path: &str,
    dest: &Path,
) -> io::Result<()> {
    stream.seek(SeekFrom::Start(0))?;
    let fs = fatfs::FileSystem::new(stream, fatfs::FsOptions::new())?;
    let root = fs.root_dir();

    // Normalize path separators
    let normalized = volume_path.replace('/', "\\");
    let normalized = normalized.trim_start_matches('\\');

    // Navigate to the file
    let parts: Vec<&str> = normalized.split('\\').collect();
    let (dir_parts, file_name) = parts.split_at(parts.len() - 1);

    let mut current_dir = root;
    for &part in dir_parts {
        current_dir = current_dir.open_dir(part)?;
    }

    let mut src = current_dir.open_file(file_name[0])?;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut dst = std::fs::File::create(dest)?;
    io::copy(&mut src, &mut dst)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// NTFS implementation
// ---------------------------------------------------------------------------

fn list_files_ntfs<S: Read + Seek>(stream: &mut S) -> io::Result<Vec<FileEntry>> {
    stream.seek(SeekFrom::Start(0))?;
    let mut ntfs = ntfs::Ntfs::new(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ntfs.read_upcase_table(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let root_dir = ntfs.root_directory(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut entries = Vec::new();
    collect_ntfs_entries(&ntfs, stream, &root_dir, "\\", &mut entries)?;
    Ok(entries)
}

fn collect_ntfs_entries<S: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut S,
    dir_file: &ntfs::NtfsFile,
    current_path: &str,
    entries: &mut Vec<FileEntry>,
) -> io::Result<()> {
    let index = dir_file.directory_index(fs)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut iter = index.entries();

    while let Some(entry) = iter.next(fs) {
        let entry = entry
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let file_name = entry.key()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing index entry key"))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let name = file_name.name().to_string_lossy();

        // Skip system/meta files
        if name.starts_with('$') || name == "." || name == ".." {
            continue;
        }

        let full_path = if current_path == "\\" {
            format!("\\{}", name)
        } else {
            format!("{}\\{}", current_path, name)
        };

        let is_dir = file_name.is_directory();
        let size = file_name.data_size();

        entries.push(FileEntry {
            name: name.to_string(),
            path: full_path.clone(),
            size,
            is_dir,
        });

        if is_dir {
            let file = entry.to_file(ntfs, fs)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            // Ignore errors recursing into directories (e.g. permission issues)
            let _ = collect_ntfs_entries(ntfs, fs, &file, &full_path, entries);
        }
    }

    Ok(())
}

fn extract_all_ntfs<S: Read + Write + Seek>(
    stream: &mut S,
    dest: &Path,
    progress: &dyn Fn(f64),
) -> io::Result<usize> {
    // First list to count files
    let file_list = list_files_ntfs(stream)?;
    let total_files = file_list.iter().filter(|f| !f.is_dir).count();

    stream.seek(SeekFrom::Start(0))?;
    let mut ntfs = ntfs::Ntfs::new(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ntfs.read_upcase_table(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let root_dir = ntfs.root_directory(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    std::fs::create_dir_all(dest)?;
    let mut count = 0;
    extract_ntfs_dir_recursive(&ntfs, stream, &root_dir, dest, &mut count, total_files, progress)?;
    Ok(count)
}

fn extract_ntfs_dir_recursive<S: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    fs: &mut S,
    dir_file: &ntfs::NtfsFile,
    dest: &Path,
    count: &mut usize,
    total: usize,
    progress: &dyn Fn(f64),
) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;

    let index = dir_file.directory_index(fs)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut iter = index.entries();

    while let Some(entry) = iter.next(fs) {
        let entry = entry
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let file_name = entry.key()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing index entry key"))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let name = file_name.name().to_string_lossy();
        if name.starts_with('$') || name == "." || name == ".." {
            continue;
        }

        let is_dir = file_name.is_directory();
        let file = entry.to_file(ntfs, fs)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if is_dir {
            let sub_dest = dest.join(&*name);
            let _ = extract_ntfs_dir_recursive(ntfs, fs, &file, &sub_dest, count, total, progress);
        } else {
            let file_dest = dest.join(&*name);
            if let Err(e) = extract_ntfs_file_data(fs, &file, &file_dest) {
                eprintln!("Warning: failed to extract {}: {}", name, e);
                continue;
            }
            *count += 1;
            if total > 0 {
                progress(*count as f64 / total as f64);
            }
        }
    }

    Ok(())
}

/// Read the $DATA attribute of an NtfsFile and write it to dest.
fn extract_ntfs_file_data<S: Read + Seek>(
    fs: &mut S,
    file: &ntfs::NtfsFile,
    dest: &Path,
) -> io::Result<()> {
    use ntfs::NtfsReadSeek;

    let data_item = file.data(fs, "")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File has no $DATA attribute"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let data_attr = data_item.to_attribute()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut data_value = data_attr.value(fs)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut output = std::fs::File::create(dest)?;
    let mut buf = [0u8; 8192];

    loop {
        let bytes_read = data_value.read(fs, &mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        if bytes_read == 0 {
            break;
        }
        output.write_all(&buf[..bytes_read])?;
    }

    Ok(())
}

fn extract_file_ntfs<S: Read + Write + Seek>(
    stream: &mut S,
    volume_path: &str,
    dest: &Path,
) -> io::Result<()> {
    use ntfs::indexes::NtfsFileNameIndex;

    stream.seek(SeekFrom::Start(0))?;
    let mut ntfs_fs = ntfs::Ntfs::new(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ntfs_fs.read_upcase_table(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let normalized = volume_path.replace('/', "\\");
    let normalized = normalized.trim_start_matches('\\');
    let parts: Vec<&str> = normalized.split('\\').collect();

    // Navigate directory tree to find the file
    let mut current = ntfs_fs.root_directory(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    for (i, &part) in parts.iter().enumerate() {
        let index = current.directory_index(stream)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let mut finder = index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs_fs, stream, part)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("'{}' not found", part)))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let file = entry.to_file(&ntfs_fs, stream)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if i == parts.len() - 1 {
            // This is the target file — extract it
            return extract_ntfs_file_data(stream, &file, dest);
        }

        current = file;
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
}

// ---------------------------------------------------------------------------
// In-memory file reading (for image preview)
// ---------------------------------------------------------------------------

/// Read a file from the volume into memory, auto-detecting filesystem.
/// `max_size` limits the read to prevent OOM on huge files.
pub fn read_file_bytes<S: Read + Write + Seek>(
    stream: &mut S,
    volume_path: &str,
    max_size: u64,
) -> io::Result<Vec<u8>> {
    let fs_type = detect_filesystem(stream)?;
    match fs_type {
        FsType::Fat => read_file_bytes_fat(stream, volume_path, max_size),
        FsType::Ntfs => read_file_bytes_ntfs(stream, volume_path, max_size),
        FsType::Unknown => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unsupported or unrecognized filesystem",
        )),
    }
}

fn read_file_bytes_fat<S: Read + Write + Seek>(
    stream: &mut S,
    volume_path: &str,
    max_size: u64,
) -> io::Result<Vec<u8>> {
    stream.seek(SeekFrom::Start(0))?;
    let fs = fatfs::FileSystem::new(stream, fatfs::FsOptions::new())?;
    let root = fs.root_dir();

    let normalized = volume_path.replace('/', "\\");
    let normalized = normalized.trim_start_matches('\\');
    let parts: Vec<&str> = normalized.split('\\').collect();
    let (dir_parts, file_name) = parts.split_at(parts.len() - 1);

    let mut current_dir = root;
    for &part in dir_parts {
        current_dir = current_dir.open_dir(part)?;
    }

    let mut src = current_dir.open_file(file_name[0])?;
    let file_size = src.seek(SeekFrom::End(0))?;
    if file_size > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("File too large for preview ({} bytes, max {})", file_size, max_size),
        ));
    }
    src.seek(SeekFrom::Start(0))?;

    let mut data = Vec::with_capacity(file_size as usize);
    io::copy(&mut src, &mut data)?;
    Ok(data)
}

fn read_file_bytes_ntfs<S: Read + Write + Seek>(
    stream: &mut S,
    volume_path: &str,
    max_size: u64,
) -> io::Result<Vec<u8>> {
    use ntfs::indexes::NtfsFileNameIndex;
    use ntfs::NtfsReadSeek;

    stream.seek(SeekFrom::Start(0))?;
    let mut ntfs_fs = ntfs::Ntfs::new(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    ntfs_fs.read_upcase_table(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let normalized = volume_path.replace('/', "\\");
    let normalized = normalized.trim_start_matches('\\');
    let parts: Vec<&str> = normalized.split('\\').collect();

    let mut current = ntfs_fs.root_directory(stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    for (i, &part) in parts.iter().enumerate() {
        let index = current.directory_index(stream)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let mut finder = index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs_fs, stream, part)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("'{}' not found", part)))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let file = entry.to_file(&ntfs_fs, stream)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if i == parts.len() - 1 {
            let data_item = file.data(stream, "")
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File has no $DATA attribute"))?
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let data_attr = data_item.to_attribute()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let attr_len = data_attr.value_length();
            if attr_len > max_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("File too large for preview ({} bytes, max {})", attr_len, max_size),
                ));
            }

            let mut data_value = data_attr.value(stream)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let mut data = Vec::with_capacity(attr_len as usize);
            let mut buf = [0u8; 8192];
            loop {
                let bytes_read = data_value.read(stream, &mut buf)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                if bytes_read == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..bytes_read]);
            }
            return Ok(data);
        }

        current = file;
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_fat_boot_signature() {
        let mut data = vec![0u8; 512];
        // FAT boot signature
        data[510] = 0x55;
        data[511] = 0xAA;
        // OEM ID "MSDOS5.0"
        data[3..11].copy_from_slice(b"MSDOS5.0");

        let mut cursor = io::Cursor::new(data);
        let fs_type = detect_filesystem(&mut cursor).unwrap();
        assert_eq!(fs_type, FsType::Fat);
    }

    #[test]
    fn test_detect_ntfs() {
        let mut data = vec![0u8; 512];
        data[510] = 0x55;
        data[511] = 0xAA;
        data[3..11].copy_from_slice(b"NTFS    ");

        let mut cursor = io::Cursor::new(data);
        let fs_type = detect_filesystem(&mut cursor).unwrap();
        assert_eq!(fs_type, FsType::Ntfs);
    }

    #[test]
    fn test_detect_unknown() {
        let data = vec![0u8; 512];
        let mut cursor = io::Cursor::new(data);
        let fs_type = detect_filesystem(&mut cursor).unwrap();
        assert_eq!(fs_type, FsType::Unknown);
    }
}
