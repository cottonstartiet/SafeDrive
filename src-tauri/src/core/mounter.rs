/// Mount/unmount decrypted TrueCrypt volumes as Windows drives via temporary VHD files.
/// Shells out to PowerShell for VHD mount/dismount (requires Administrator privileges).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::vhd;

/// Holds state for a mounted VHD.
pub struct MountHandle {
    vhd_path: PathBuf,
    volume_path: PathBuf,
    password: String,
    drive_letter: Option<String>,
    mounted: bool,
}

impl MountHandle {
    pub fn drive_letter(&self) -> Option<&str> {
        self.drive_letter.as_deref()
    }

    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    pub fn vhd_path(&self) -> &Path {
        &self.vhd_path
    }
}

/// Mount stage for progress reporting.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MountProgress {
    pub stage: String,
    pub progress: f64,
}

/// Mount a TrueCrypt volume as a Windows drive.
/// Creates a temp VHD, copies decrypted data into it, and mounts via PowerShell.
/// The `on_progress` callback receives stage-based progress updates.
pub fn mount<S: Read + Seek>(
    decrypted_stream: &mut S,
    volume_path: &Path,
    password: &str,
    on_progress: &dyn Fn(MountProgress),
) -> io::Result<MountHandle> {
    // Create temp VHD path
    let vhd_path = std::env::temp_dir().join(format!(
        "tc_{:x}.vhd",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    // Create VHD from decrypted data (0–90% of total progress)
    on_progress(MountProgress { stage: "creating_vhd".into(), progress: 0.0 });
    let mut vhd_file = File::create(&vhd_path)?;
    vhd::create_vhd(decrypted_stream, &mut vhd_file, &|vhd_progress| {
        on_progress(MountProgress {
            stage: "creating_vhd".into(),
            progress: vhd_progress * 0.9,
        });
    })?;
    drop(vhd_file);

    // Mount the VHD (90–95%)
    on_progress(MountProgress { stage: "mounting".into(), progress: 0.9 });
    mount_vhd(&vhd_path)?;

    // Wait for Windows to recognize the volume and detect drive letter (95–100%)
    on_progress(MountProgress { stage: "detecting".into(), progress: 0.95 });
    std::thread::sleep(std::time::Duration::from_secs(2));

    let mut drive_letter = detect_drive_letter(&vhd_path);
    if drive_letter.is_none() {
        std::thread::sleep(std::time::Duration::from_secs(3));
        drive_letter = detect_drive_letter(&vhd_path);
    }

    on_progress(MountProgress { stage: "done".into(), progress: 1.0 });

    Ok(MountHandle {
        vhd_path,
        volume_path: volume_path.to_path_buf(),
        password: password.to_string(),
        drive_letter,
        mounted: true,
    })
}

/// Unmount the VHD and optionally write changes back to the encrypted volume.
pub fn unmount(handle: &mut MountHandle, write_back: bool) -> io::Result<()> {
    if !handle.mounted {
        return Ok(());
    }

    dismount_vhd(&handle.vhd_path)?;
    handle.mounted = false;

    std::thread::sleep(std::time::Duration::from_millis(1000));

    if write_back {
        write_back_to_volume(
            &handle.vhd_path,
            &handle.volume_path,
            &handle.password,
        )?;
    }

    // Clean up temp VHD
    if handle.vhd_path.exists() {
        if let Err(e) = fs::remove_file(&handle.vhd_path) {
            eprintln!("Warning: Could not delete temp VHD: {}", e);
        }
    }

    handle.drive_letter = None;
    Ok(())
}

/// Write VHD partition data back to the encrypted volume.
fn write_back_to_volume(
    vhd_path: &Path,
    volume_path: &Path,
    password: &str,
) -> io::Result<()> {
    use crate::core::volume::TrueCryptVolume;

    let mut volume = TrueCryptVolume::open(volume_path, password, true)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let data_size = volume.decrypted_stream().data_area_length();

    let mut vhd_file = OpenOptions::new().read(true).open(vhd_path)?;
    vhd_file.seek(SeekFrom::Start(vhd::partition_offset()))?;

    let stream = volume.decrypted_stream();
    stream.seek(SeekFrom::Start(0))?;

    let mut buffer = vec![0u8; 64 * 1024];
    let mut remaining = data_size;

    while remaining > 0 {
        let to_read = buffer.len().min(remaining as usize);
        let n = vhd_file.read(&mut buffer[..to_read])?;
        if n == 0 {
            break;
        }
        stream.write_all(&buffer[..n])?;
        remaining -= n as u64;
    }

    stream.flush()?;
    Ok(())
}

/// Check if the current process is running with admin privileges.
pub fn is_elevated() -> bool {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .output();

    match output {
        Ok(out) => {
            let result = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            result == "true"
        }
        Err(_) => false,
    }
}

fn mount_vhd(vhd_path: &Path) -> io::Result<()> {
    let script = format!(
        "Mount-DiskImage -ImagePath '{}' -StorageType VHD -Access ReadWrite",
        vhd_path.display()
    );
    run_powershell(&script)
}

fn dismount_vhd(vhd_path: &Path) -> io::Result<()> {
    let script = format!(
        "Dismount-DiskImage -ImagePath '{}'",
        vhd_path.display()
    );
    run_powershell(&script)
}

fn detect_drive_letter(vhd_path: &Path) -> Option<String> {
    let script = format!(
        r#"$image = Get-DiskImage -ImagePath '{}'
if ($image.Number -ne $null) {{
    $partitions = Get-Partition -DiskNumber $image.Number -ErrorAction SilentlyContinue
    foreach ($p in $partitions) {{
        if ($p.DriveLetter) {{
            Write-Output "$($p.DriveLetter):"
            break
        }}
    }}
}}"#,
        vhd_path.display()
    );

    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()
        .ok()?;

    let letter = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if letter.len() == 2 && letter.ends_with(':') {
        Some(letter)
    } else {
        None
    }
}

fn run_powershell(script: &str) -> io::Result<()> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "PowerShell command failed (exit code {:?}): {}. Ensure you are running as Administrator.",
                output.status.code(),
                stderr.trim()
            ),
        ));
    }

    Ok(())
}
