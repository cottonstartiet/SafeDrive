# TrueCrypt Volume Reader — Implementation Spec

> **Scope:** First iteration. Open an existing TrueCrypt volume, decrypt it, browse files, extract files, and optionally mount as a Windows drive.

---

## 1. Overview

The Reader is the core of the app. Given a `.tc` volume file and a password, it must:

1. Parse and decrypt the volume header (trying all PRF × cipher combinations)
2. Provide a decrypted byte stream over the volume's data area
3. Detect the filesystem (FAT / NTFS / ext2/3/4)
4. List and extract files
5. (Optional) Mount the decrypted data as a Windows drive via VHD

---

## 2. Architecture

```
Tauri IPC
   │
   ▼
┌──────────────────────────────────────────────┐
│  Tauri Commands (src-tauri/src/commands/)     │
│  open_volume, list_files, extract_files,     │
│  mount_volume, unmount_volume                │
└──────────┬───────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│  Core Library  (src-tauri/src/core/)         │
│                                              │
│  volume.rs         TrueCryptVolume::open()   │
│  volume_header.rs  VolumeHeader::try_decrypt │
│  decrypted_stream.rs  Read/Write/Seek stream │
│  filesystem.rs     detect + open FS          │
│  key_derivation.rs PBKDF2 × 4 PRFs          │
│  cipher.rs         AES/Serpent/Twofish       │
│  xts.rs            XTS encrypt + decrypt     │
│  constants.rs      TrueCrypt constants       │
│  crc32.rs          CRC-32 (or crate)         │
│  vhd.rs            MBR + VHD footer          │
│  mounter.rs        VHD mount/unmount         │
└──────────────────────────────────────────────┘
```

---

## 3. Component Specifications

### 3.1 Constants (`constants.rs`)

Port all values from `TrueCryptConstants.cs`:

| Constant | Value | Purpose |
|----------|-------|---------|
| `VOLUME_HEADER_SIZE` | 65536 (64 KB) | Single header slot |
| `VOLUME_HEADER_EFFECTIVE_SIZE` | 512 | Parsed header bytes |
| `VOLUME_HEADER_GROUP_SIZE` | 131072 (128 KB) | Primary + hidden header |
| `VOLUME_DATA_OFFSET` | 131072 | Where encrypted data begins |
| `HIDDEN_VOLUME_HEADER_OFFSET` | 65536 | Hidden header location |
| `SALT_SIZE` | 64 | PKCS5 salt |
| `MASTER_KEY_DATA_SIZE` | 256 | Key material in header |
| `ENCRYPTION_DATA_UNIT_SIZE` | 512 | XTS sector size |
| `BYTES_PER_XTS_BLOCK` | 16 | AES block size |
| `BLOCKS_PER_XTS_DATA_UNIT` | 32 | 512 / 16 |
| `MAGIC_TRUE` | `0x54525545` | ASCII "TRUE" |
| Header field offsets | see C# source | `OFFSET_MAGIC = 64`, `OFFSET_VERSION = 68`, etc. |

### 3.2 CRC-32 (`crc32.rs`)

- Use `crc32fast` crate (SIMD-accelerated)
- Or port the 256-entry table: polynomial `0xEDB88320`, init `0xFFFFFFFF`, final XOR `0xFFFFFFFF`
- Must match TrueCrypt's CRC-32/ISO-HDLC

### 3.3 Key Derivation (`key_derivation.rs`)

**PRFs to support (all via RustCrypto crates):**

| PRF | Crate | PBKDF2 Iterations (non-boot) |
|-----|-------|------------------------------|
| RIPEMD-160 | `ripemd` | 2000 |
| SHA-512 | `sha2` | 1000 |
| Whirlpool | `whirlpool` | 1000 |
| SHA-1 | `sha1` | 2000 |

**Function signature:**
```rust
fn derive_key(password: &[u8], salt: &[u8], prf: Prf, boot: bool) -> [u8; 256];
```

- Output is always 256 bytes (`MASTER_KEY_DATA_SIZE`)
- Use `pbkdf2::pbkdf2_hmac` from the `pbkdf2` crate

### 3.4 Cipher Engines (`cipher.rs`)

**Block ciphers:** AES-256, Serpent-256, Twofish-256  
**All use 128-bit (16-byte) blocks, 256-bit (32-byte) keys.**

```rust
enum CipherType { Aes, Serpent, Twofish }

struct CipherEngine {
    encrypt: Box<dyn BlockEncrypt>,
    decrypt: Box<dyn BlockDecrypt>,
}

impl CipherEngine {
    fn encrypt_block(&self, block: &mut [u8; 16]);
    fn decrypt_block(&self, block: &mut [u8; 16]);
}
```

**Encryption algorithms (cascade table):**

| Name | Ciphers (in order) | Total key size |
|------|-------------------|----------------|
| AES | AES | 32 bytes |
| Serpent | Serpent | 32 bytes |
| Twofish | Twofish | 32 bytes |
| Twofish-AES | Twofish, AES | 64 bytes |
| Serpent-Twofish-AES | Serpent, Twofish, AES | 96 bytes |
| AES-Serpent | AES, Serpent | 64 bytes |
| AES-Twofish-Serpent | AES, Twofish, Serpent | 96 bytes |
| Serpent-Twofish | Serpent, Twofish | 64 bytes |

**`create_engines(derived_key)`** splits key material into primary + secondary (XTS) key sets:
- Primary keys: `derived_key[0..key_size]`
- Secondary keys: `derived_key[key_size..key_size*2]`

### 3.5 XTS Decrypt (`xts.rs`)

Port from `XtsDecryptor.cs`. IEEE P1619 XTS mode:

1. Compute tweak: encode `data_unit_no` as little-endian u64 into 16-byte block, encrypt with secondary key
2. For each 16-byte block in the data unit:
   - XOR with tweak → decrypt with primary key → XOR with tweak
   - Advance tweak via `gf_mul_128` (left-shift + conditional XOR `0x87`)
3. **Cascade decryption:** apply ciphers in **reverse** order, each doing a full XTS pass

```rust
fn decrypt_xts(data: &mut [u8], data_unit_no: u64, primary: &CipherEngine, secondary: &CipherEngine);
fn decrypt_xts_cascade(data: &mut [u8], data_unit_no: u64, primaries: &[CipherEngine], secondaries: &[CipherEngine]);
```

### 3.6 Volume Header (`volume_header.rs`)

**`VolumeHeader::try_decrypt(header_bytes: &[u8; 512], password: &[u8]) -> Option<VolumeHeader>`**

Algorithm:
1. Extract salt from bytes `[0..64]`
2. For each PRF in `[RIPEMD-160, SHA-512, Whirlpool, SHA-1]`:
   a. Derive 256-byte key
   b. For each encryption algorithm (8 total):
      - Check `key_size * 2 <= 256`
      - Create cipher engines from derived key
      - Copy header, decrypt bytes `[64..512]` using XTS with `data_unit_no = 0`
      - Check magic `"TRUE"` at offset 64
      - Validate header CRC (bytes `[64..252]` vs uint32 at offset 252)
      - Validate key area CRC (bytes `[256..512]` vs uint32 at offset 72)
      - If all pass → parse and return header fields
3. Return `None` if no combination works

**Parsed fields:**

```rust
struct VolumeHeader {
    header_version: u16,
    required_program_version: u16,
    hidden_volume_size: u64,
    volume_size: u64,
    encrypted_area_start: u64,
    encrypted_area_length: u64,
    flags: u32,
    sector_size: u32,
    master_key_data: [u8; 256],
    salt: [u8; 64],
    encryption_algorithm: EncryptionAlgorithm,
    prf: Prf,
}
```

### 3.7 Decrypted Volume Stream (`decrypted_stream.rs`)

A `Read + Write + Seek` stream wrapping the raw file:

- Position 0 = first byte of the filesystem (data area)
- **Read:** locate sector → read encrypted sector from file → XTS decrypt → copy requested bytes
- **Write:** read-modify-write for partial sectors, XTS encrypt, write back
- **Data unit number** = `absolute_file_offset / 512` (NOT relative to data area — matches TrueCrypt behavior)
- For hidden volumes: `data_area_offset = file_length - hidden_volume_size - VOLUME_HEADER_GROUP_SIZE`

### 3.8 Filesystem Detection & Access (`filesystem.rs`)

1. Read first 512 bytes of decrypted stream
2. Check OEM ID at bytes `[3..11]`:
   - `"NTFS"` → try `ntfs` crate
   - Otherwise → try `fatfs` crate, then `ntfs`, then `ext4-rs`
3. Provide unified trait for listing/extracting:

```rust
trait VolumeFilesystem {
    fn list_files(&self, path: &str) -> Vec<FileEntry>;
    fn extract_file(&self, path: &str, dest: &Path) -> Result<()>;
    fn extract_all(&self, dest: &Path, progress: impl Fn(f64)) -> Result<usize>;
}
```

### 3.9 VHD + Mounter (`vhd.rs`, `mounter.rs`)

**VHD creation:**
- Build MBR with one partition (type `0x07`, LBA start at 1MB offset)
- Copy decrypted stream into partition area
- Append 512-byte VHD footer (`"conectix"`, fixed disk type `0x02`, CHS geometry)

**Mount/unmount:** shell to PowerShell:
- `Mount-DiskImage -ImagePath '<path>' -StorageType VHD -Access ReadWrite`
- `Dismount-DiskImage -ImagePath '<path>'`
- Detect drive letter via `Get-DiskImage` → `Get-Partition`

**Write-back on unmount:**
- Read VHD partition data (skip 1MB MBR area)
- Write to `DecryptedStream` (which re-encrypts transparently)
- Delete temp VHD

### 3.10 High-Level API (`volume.rs`)

```rust
impl TrueCryptVolume {
    /// Try primary header, then hidden (offset 64KB), then backup (end of file)
    pub fn open(path: &Path, password: &str, writable: bool) -> Result<Self>;
    pub fn header(&self) -> &VolumeHeader;
    pub fn decrypted_stream(&self) -> &DecryptedStream;
    pub fn open_filesystem(&self) -> Result<Box<dyn VolumeFilesystem>>;
    pub fn list_files(&self) -> Result<Vec<FileEntry>>;
    pub fn extract_all(&self, dest: &Path, progress: impl Fn(f64)) -> Result<usize>;
    pub fn extract_file(&self, volume_path: &str, dest: &Path) -> Result<()>;
}
```

---

## 4. Tauri Commands (IPC)

| Command | Parameters | Returns |
|---------|-----------|---------|
| `open_volume` | `path: String, password: String` | `VolumeInfo { encryption, hash, version, size, hidden }` |
| `list_files` | `path: String` (in volume) | `Vec<FileEntry { name, path, size, is_dir }>` |
| `extract_files` | `dest: String, paths: Vec<String>` | streams progress events |
| `extract_all` | `dest: String` | streams progress events |
| `mount_volume` | (uses already-opened volume) | `{ drive_letter: String }` |
| `unmount_volume` | | `{ success: bool }` |
| `close_volume` | | — |

---

## 5. UI Screens (Reader)

1. **Home** — Drag-and-drop or browse for `.tc` file
2. **Password Dialog** — Password input with masked field, "Unlock" button, spinner during decryption
3. **Volume Info** — Show encryption algorithm, hash, version, size, hidden volume status
4. **File Browser** — Tree/list view of volume contents, select files, "Extract" / "Extract All" buttons
5. **Mount Panel** — "Mount as Drive" button (with admin elevation prompt), shows assigned drive letter, "Unmount" button

---

## 6. Rust Crate Dependencies

```toml
[dependencies]
# Crypto
aes = "0.8"
serpent = "0.5"
twofish = "0.7"
cipher = "0.4"          # BlockEncrypt/BlockDecrypt traits
pbkdf2 = "0.12"
hmac = "0.12"
sha1 = "0.10"
sha2 = "0.10"
ripemd = "0.1"
whirlpool = "0.10"

# Utilities
crc32fast = "1"
byteorder = "1"

# Filesystem
fatfs = "0.4"
ntfs = "0.4"            # Read-only NTFS

# Tauri
tauri = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

---

## 7. Testing Strategy

- **Unit tests:** each crypto component tested against known TrueCrypt test vectors
- **Integration test:** open a real `.tc` volume (committed as test fixture, small FAT volume) and verify file extraction matches expected content
- **Cross-validation:** decrypt same volume with both C# app and Rust app, compare byte-for-byte output
