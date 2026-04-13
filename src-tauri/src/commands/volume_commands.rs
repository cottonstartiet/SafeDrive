/// Tauri IPC commands for TrueCrypt volume operations.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use tauri::State;

use crate::core::filesystem::{self, FileEntry, FsType};
use crate::core::mounter::{self, MountHandle, MountProgress};
use crate::core::volume::TrueCryptVolume;
use crate::core::volume_header::VolumeInfo;

/// Application state holding the currently opened volume and mount handle.
pub struct AppState {
    pub volume: Mutex<Option<OpenedVolume>>,
    pub mount_handle: Mutex<Option<MountHandle>>,
}

pub struct OpenedVolume {
    pub volume: TrueCryptVolume,
    pub path: PathBuf,
    pub password: String,
    pub fs_type: FsType,
}

#[derive(Serialize)]
pub struct OpenVolumeResult {
    pub info: VolumeInfo,
    pub fs_type: String,
}

#[derive(Serialize)]
pub struct MountResult {
    pub drive_letter: Option<String>,
}

#[derive(Serialize)]
pub struct ImagePreviewResult {
    pub data: String,
    pub mime_type: String,
}

const IMAGE_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "ico", "tiff", "tif",
];

const MAX_PREVIEW_SIZE: u64 = 50 * 1024 * 1024; // 50 MB

#[tauri::command]
pub fn open_volume(
    path: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<OpenVolumeResult, String> {
    let volume_path = PathBuf::from(&path);

    let mut volume = TrueCryptVolume::open(&volume_path, &password, false)
        .map_err(|e| e.to_string())?;

    let info = volume.header().to_info();

    let fs_type = filesystem::detect_filesystem(volume.decrypted_stream())
        .unwrap_or(FsType::Unknown);

    let fs_type_str = match fs_type {
        FsType::Fat => "FAT",
        FsType::Ntfs => "NTFS",
        FsType::Unknown => "Unknown",
    }
    .to_string();

    let opened = OpenedVolume {
        volume,
        path: volume_path,
        password,
        fs_type,
    };

    let mut vol_lock = state.volume.lock().map_err(|e| e.to_string())?;
    *vol_lock = Some(opened);

    Ok(OpenVolumeResult {
        info,
        fs_type: fs_type_str,
    })
}

#[tauri::command]
pub fn list_files(
    path: String,
    state: State<'_, AppState>,
) -> Result<Vec<FileEntry>, String> {
    let mut vol_lock = state.volume.lock().map_err(|e| e.to_string())?;
    let opened = vol_lock.as_mut().ok_or("No volume is currently open")?;

    let stream = opened.volume.decrypted_stream();
    let entries = filesystem::list_files(stream).map_err(|e| e.to_string())?;

    // Filter by path prefix if not root
    if path == "\\" || path == "/" || path.is_empty() {
        Ok(entries)
    } else {
        let normalized = path.replace('/', "\\");
        Ok(entries
            .into_iter()
            .filter(|e| e.path.starts_with(&normalized))
            .collect())
    }
}

#[tauri::command]
pub fn extract_all(
    dest: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<usize, String> {
    use tauri::Emitter;

    let mut vol_lock = state.volume.lock().map_err(|e| e.to_string())?;
    let opened = vol_lock.as_mut().ok_or("No volume is currently open")?;

    let dest_path = PathBuf::from(&dest);
    let handle = app_handle.clone();

    let count = filesystem::extract_all(
        opened.volume.decrypted_stream(),
        &dest_path,
        &move |progress| {
            let _ = handle.emit("extract-progress", progress);
        },
    )
    .map_err(|e| e.to_string())?;

    Ok(count)
}

#[tauri::command]
pub fn extract_files(
    dest: String,
    paths: Vec<String>,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<usize, String> {
    use tauri::Emitter;

    let mut vol_lock = state.volume.lock().map_err(|e| e.to_string())?;
    let opened = vol_lock.as_mut().ok_or("No volume is currently open")?;

    let dest_path = PathBuf::from(&dest);
    let total = paths.len();
    let handle = app_handle.clone();

    for (i, volume_path) in paths.iter().enumerate() {
        let file_name = volume_path
            .rsplit('\\')
            .next()
            .or_else(|| volume_path.rsplit('/').next())
            .unwrap_or(volume_path);

        let file_dest = dest_path.join(file_name);

        filesystem::extract_file(
            opened.volume.decrypted_stream(),
            volume_path,
            &file_dest,
        )
        .map_err(|e| format!("Failed to extract {}: {}", volume_path, e))?;

        let _ = handle.emit("extract-progress", (i + 1) as f64 / total as f64);
    }

    Ok(total)
}

#[tauri::command]
pub async fn mount_volume(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<MountResult, String> {
    use tauri::Emitter;

    if !mounter::is_elevated() {
        return Err("Administrator privileges required for mounting. Please restart the app as Administrator.".into());
    }

    // Clone path + password so we can release the lock before spawning
    let (volume_path, password) = {
        let vol_lock = state.volume.lock().map_err(|e| e.to_string())?;
        let opened = vol_lock.as_ref().ok_or("No volume is currently open")?;
        (opened.path.clone(), opened.password.clone())
    };

    let handle = app_handle.clone();

    // Spawn the heavy work on a blocking thread to keep the UI responsive
    let result = tauri::async_runtime::spawn_blocking(move || {
        // Re-open the volume on this thread (DecryptedStream is !Send)
        let mut volume = TrueCryptVolume::open(&volume_path, &password, false)
            .map_err(|e| e.to_string())?;

        let mount_handle = mounter::mount(
            volume.decrypted_stream(),
            &volume_path,
            &password,
            &|progress: MountProgress| {
                let _ = handle.emit("mount-progress", &progress);
            },
        )
        .map_err(|e| e.to_string())?;

        Ok::<MountHandle, String>(mount_handle)
    })
    .await
    .map_err(|e| format!("Mount task panicked: {}", e))?
    .map_err(|e: String| e)?;

    let drive_letter = result.drive_letter().map(|s| s.to_string());

    let mut mount_lock = state.mount_handle.lock().map_err(|e| e.to_string())?;
    *mount_lock = Some(result);

    Ok(MountResult { drive_letter })
}

#[tauri::command]
pub async fn unmount_volume(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<bool, String> {
    use tauri::Emitter;

    // Take the mount handle out (we'll consume it)
    let mut mount_handle = {
        let mut mount_lock = state.mount_handle.lock().map_err(|e| e.to_string())?;
        mount_lock.take().ok_or("No volume is currently mounted")?
    };

    let handle = app_handle.clone();

    let result = tauri::async_runtime::spawn_blocking(move || {
        handle.emit("unmount-progress", "unmounting").ok();
        mounter::unmount(&mut mount_handle, true).map_err(|e| e.to_string())?;
        handle.emit("unmount-progress", "done").ok();
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("Unmount task panicked: {}", e))?
    .map_err(|e: String| e)?;

    let _ = result;
    Ok(true)
}

#[tauri::command]
pub fn close_volume(
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Unmount first if mounted
    {
        let mut mount_lock = state.mount_handle.lock().map_err(|e| e.to_string())?;
        if let Some(handle) = mount_lock.as_mut() {
            if handle.is_mounted() {
                let _ = mounter::unmount(handle, true);
            }
        }
        *mount_lock = None;
    }

    let mut vol_lock = state.volume.lock().map_err(|e| e.to_string())?;
    *vol_lock = None;

    Ok(())
}

#[tauri::command]
pub fn is_elevated() -> bool {
    mounter::is_elevated()
}

#[tauri::command]
pub fn preview_image(
    volume_path: String,
    state: State<'_, AppState>,
) -> Result<ImagePreviewResult, String> {
    use base64::Engine;

    // Validate image extension
    let ext = volume_path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    if !IMAGE_EXTENSIONS.contains(&ext.as_str()) {
        return Err(format!("Unsupported image format: .{}", ext));
    }

    let mime_type = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "tiff" | "tif" => "image/tiff",
        _ => "application/octet-stream",
    }
    .to_string();

    let mut vol_lock = state.volume.lock().map_err(|e| e.to_string())?;
    let opened = vol_lock.as_mut().ok_or("No volume is currently open")?;

    let bytes = filesystem::read_file_bytes(
        opened.volume.decrypted_stream(),
        &volume_path,
        MAX_PREVIEW_SIZE,
    )
    .map_err(|e| e.to_string())?;

    let data = base64::engine::general_purpose::STANDARD.encode(&bytes);

    Ok(ImagePreviewResult { data, mime_type })
}

#[tauri::command]
pub fn verify_lock_password(
    password: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let vol_lock = state.volume.lock().map_err(|e| e.to_string())?;
    let opened = vol_lock.as_ref().ok_or("No volume is currently open")?;
    Ok(opened.password == password)
}
