# SafeDrive

SafeDrive is a lightweight desktop application for securely accessing and managing encrypted volumes. It is built with [Tauri](https://tauri.app/), React, and TypeScript on the front end and a Rust backend that implements the TrueCrypt volume format from scratch — no external tools or drivers required.

---

## Overview

SafeDrive lets you open, decrypt, browse, and extract files from existing encrypted volumes without needing to install TrueCrypt or VeraCrypt. Simply point it at a `.tc` or `.hc` file, enter your password, and you have immediate access to all the files inside. On Windows you can also mount the volume as a virtual drive letter for seamless read/write access with any application.

> **Note:** Creating new encrypted volumes is not yet supported but is coming soon.

---

## Features

### Open & Decrypt Existing Volumes
- Reads existing **TrueCrypt** and **VeraCrypt**-compatible encrypted volumes (`.tc` and `.hc` files).
- Supports all standard **TrueCrypt encryption algorithms**: AES-256, Serpent-256, and Twofish-256 (including cascades).
- Supports all standard **key-derivation PRFs**: HMAC-RIPEMD-160, HMAC-SHA-512, HMAC-Whirlpool, and HMAC-SHA-1 — the correct one is detected automatically.
- Detects and handles **hidden volumes**.

### File Browser
- Browse the full directory tree inside a decrypted volume.
- View file names, sizes, and folder structure at a glance.
- **Preview images** (JPEG, PNG, etc.) directly inside the app without extracting them first.

### File Extraction
- **Extract all files** from a volume to a folder of your choice in one click.
- **Extract selected files** — pick individual files or folders to extract.
- Real-time **progress bar** during extraction.

### Virtual Drive Mounting *(Windows)*
- **Mount** the decrypted volume as a Windows drive letter via a temporary VHD, giving any application on your system transparent read/write access.
- **Unmount** the volume when you are done; changes are automatically saved back into the encrypted container.
- Live progress indicator and stage feedback during the mount process.

### Security
- **Auto-lock screen** — the app automatically covers the volume contents whenever its window loses focus, protecting against shoulder-surfing.
- A separate **lock-screen overlay** requires re-authentication before the content is revealed again.
- Passwords are never written to disk; all decryption happens in memory.

### Convenience
- **Drag & drop** a volume file anywhere onto the app to open it instantly.
- **Recent drives** list remembers the last 10 volumes you opened (paths only — no passwords stored).
- **Auto-updater** notifies you when a new version of SafeDrive is available.

### Coming Soon
- **Create Drive** — create a brand-new encrypted TrueCrypt-compatible volume from scratch.

---

## How It Works

1. **Open a volume** — drag and drop a `.tc` / `.hc` file onto the app, or use the *Open Drive* button to browse for one.
2. **Enter your password** — SafeDrive tries every supported cipher/PRF combination automatically until the header decrypts successfully (verified with the built-in CRC checksum). No algorithm selection is needed.
3. **Browse and extract** — once decrypted, the file system inside the volume (FAT32 / exFAT / NTFS) is parsed entirely in Rust. You can browse directories, preview images, and extract any files you need.
4. **Mount as a drive** *(Windows)* — optionally write the decrypted volume to a temporary VHD and mount it via the Windows Virtual Disk API, assigning a real drive letter so any application can access it transparently.
5. **Close the volume** — use *Close Volume* or *Unmount* when you are finished. All decrypted data is cleared from memory.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| UI | React 18, TypeScript, Tailwind CSS, shadcn/ui |
| Desktop shell | Tauri v2 (Rust) |
| Crypto (cipher) | AES-256, Serpent-256, Twofish-256 via pure-Rust crates |
| Crypto (KDF) | PBKDF2 with HMAC-RIPEMD-160 / SHA-512 / Whirlpool / SHA-1 |
| File system parsing | Custom FAT/NTFS reader in Rust |
| Virtual disk (Windows) | Windows VHD APIs via Rust FFI |

---

## Development Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
