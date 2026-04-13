# TrueCrypt Volume Creator — Implementation Spec

> **Scope:** Second iteration. Create new TrueCrypt-compatible encrypted volumes. Depends on all Reader components being complete.

---

## 1. Overview

The Creator builds a new TrueCrypt volume file from scratch:

1. Generate cryptographic random salt + master key
2. Derive header encryption key via PBKDF2
3. Build and encrypt primary + backup volume headers
4. Write a random-filled encrypted data area (no filesystem formatting)
5. Auto-mount the new volume as a VHD so the OS can format it (user chooses NTFS/exFAT/FAT32)
6. On unmount, write the formatted data back into the encrypted volume

**Key design decision:** No in-code NTFS formatting. The OS handles filesystem creation via the standard "Format Disk" dialog after VHD mount. This avoids the need for an NTFS formatting library (none exists in Rust) and gives the user filesystem choice.

---

## 2. Creation Flow

```
User Input                     Rust Backend                         OS
──────────                     ────────────                         ──
path, size, password ──►  1. Validate (min size, file not exists)
                          2. Generate salt (64 bytes, CSPRNG)
                          3. Generate master key (256 bytes, CSPRNG)
                          4. Derive header key (PBKDF2-HMAC-SHA512)
                          5. Build 512-byte header
                          6. Encrypt header bytes [64..512] via XTS
                          7. Create volume file:
                             ├── Primary header (512B + random pad to 64KB)
                             ├── Hidden header area (64KB random)
                             ├── Data area (random-filled, encrypted)
                             ├── Backup primary header (re-derived key)
                             └── Backup hidden header (64KB random)
                          8. Auto-mount as VHD ──────────────────► Windows shows
                                                                   "Format Disk"
                                                                   dialog
                          9. Wait for user ◄──── User formats ◄── User picks
                                                  and uses volume   NTFS/exFAT/etc
                         10. Unmount + write back encrypted data
```

---

## 3. Component Specifications

### 3.1 XTS Encrypt (`xts.rs` — shared with Reader)

Port from `XtsEncryptor.cs`. Same as decrypt but:
- Uses `encrypt_block` instead of `decrypt_block`
- **Cascade encryption:** apply ciphers in **forward** order (opposite of decrypt)

```rust
fn encrypt_xts(data: &mut [u8], data_unit_no: u64, primary: &CipherEngine, secondary: &CipherEngine);
fn encrypt_xts_cascade(data: &mut [u8], data_unit_no: u64, primaries: &[CipherEngine], secondaries: &[CipherEngine]);
```

> Note: XTS encrypt is also needed by Reader's `DecryptedStream::write()` for the mount write-back path. It's listed here because the Creator is the primary user.

### 3.2 Header Builder (`volume_header.rs` — extend Reader's module)

**`VolumeHeader::build(...) -> [u8; 512]`**

Builds an unencrypted header, then encrypts it:

1. Write salt at bytes `[0..64]`
2. Write master key data at bytes `[256..512]`
3. Compute key area CRC32 (of bytes `[256..512]`), write at offset 72
4. Write magic `"TRUE"` at offset 64
5. Write header version (`0x0005`) at offset 68
6. Write required program version (`0x0700`) at offset 70
7. Write volume size, encrypted area start/length, sector size (512), flags (0)
8. Compute header CRC32 (of bytes `[64..252]`), write at offset 252
9. Encrypt bytes `[64..512]` with XTS using derived key, data unit 0

### 3.3 Volume Creator (`volume_creator.rs`)

**Defaults:**
- Encryption: AES-256 (first entry in cascade table)
- PRF: SHA-512
- Header version: 5 (TrueCrypt 7.x compatible)

**`VolumeCreator::create(path, size_bytes, password, progress_cb)`**

Steps:
1. Validate: file doesn't exist, size ≥ `VOLUME_HEADER_GROUP_SIZE * 2 + 1MB`
2. Compute: `data_area_size = size_bytes - 128KB - 128KB`
3. Generate: `salt` (64 bytes), `master_key` (256 bytes) via CSPRNG
4. Derive header key: `pbkdf2_hmac_sha512(password, salt, 1000)`
5. Build primary header → encrypt
6. **Write volume file:**
   - Offset 0: primary header (512B) + random padding (to 64KB)
   - Offset 64KB: hidden header area (64KB of random data)
   - Offset 128KB: **encrypted random data** for the data area
     - Generate random data in 64KB chunks
     - Encrypt each 512-byte sector with XTS using master key
     - Data unit number = `absolute_file_offset / 512`
   - End - 128KB: backup primary header (re-derived with fresh salt)
   - End - 64KB: backup hidden header (random)
7. Report progress via callback (0.0 → 1.0)

### 3.4 Post-Creation Mount Flow

After `create()` completes:

1. App calls existing `mount_volume` (from Reader's mounter)
2. Windows detects unformatted partition, shows "Format Disk" dialog
3. Tauri UI displays guidance: *"Your new volume is mounted. Windows will ask you to format it — choose NTFS, exFAT, or FAT32."*
4. User formats via OS dialog
5. User clicks "Unmount" in app
6. App calls `unmount_volume` → reads VHD partition data → re-encrypts → writes back to volume
7. Done — volume is now a fully formatted, encrypted TrueCrypt container

---

## 4. Tauri Commands (IPC)

| Command | Parameters | Returns |
|---------|-----------|---------|
| `create_volume` | `path: String, size_bytes: u64, password: String` | streams progress events, then `{ success: bool }` |
| `create_and_mount` | `path: String, size_bytes: u64, password: String` | streams progress events, then `{ drive_letter: String }` |

Both commands emit Tauri events for progress:
```json
{ "event": "create_progress", "payload": { "percent": 45, "stage": "encrypting_data" } }
```

---

## 5. UI Screens (Creator)

1. **Create Wizard — Step 1:** Choose file path (save dialog) and volume size (slider or input: MB/GB)
2. **Create Wizard — Step 2:** Enter password + confirm password, strength indicator
3. **Create Wizard — Step 3:** Progress bar during creation (key derivation → header → data encryption)
4. **Create Wizard — Step 4:** "Volume created! Mounting now..." → shows drive letter → instructions to format
5. **Post-format:** "Your encrypted volume is ready. Unmount when done." → Unmount button

---

## 6. Additional Crate Dependencies (beyond Reader)

```toml
# None additional — Creator reuses all Reader crates
# CSPRNG uses Rust's `rand` or `getrandom` (already transitive dep of crypto crates)
```

---

## 7. Testing Strategy

- **Round-trip test:** Create volume with Rust → open with C# app → verify header decrypts and data area reads correctly
- **Cross-tool test:** Create volume with Rust → mount → format NTFS → add files → unmount → reopen → verify files intact
- **Header validation:** Build header → encrypt → decrypt → verify all fields match and CRCs pass
- **Edge cases:** minimum volume size, maximum volume size (>4GB), special characters in password, empty data area

---

## 8. Prerequisite: Reader Spec Must Be Complete

The Creator depends on these Reader components:
- `constants.rs` — all TrueCrypt constants
- `crc32.rs` — header CRC validation
- `key_derivation.rs` — PBKDF2 key derivation
- `cipher.rs` — cipher engines
- `xts.rs` — both encrypt AND decrypt
- `volume_header.rs` — header build + encrypt (extended here)
- `decrypted_stream.rs` — write path for mount write-back
- `mounter.rs` — VHD mount/unmount for post-creation formatting
