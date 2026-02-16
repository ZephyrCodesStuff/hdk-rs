//! PS3 PKG file format structures.
//!
//! A PS3 `.pkg` file has the following high-level layout:
//!
//! | Region           | Offset          | Notes                              |
//! |------------------|-----------------|------------------------------------|
//! | Main header      | `0x00`–`0xBF`   | Always plaintext                   |
//! | Extended header  | `0xB0`–`0x10F`  | Always plaintext                   |
//! | File entry table | `data_offset`   | Encrypted for retail, plain debug  |
//! | File names       | (relative)      | Encrypted for retail, plain debug  |
//! | File data        | (relative)      | Encrypted for retail, plain debug  |

use core::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PKG magic: `\x7FPKG` → `0x7F504B47` (big-endian).
pub const PKG_MAGIC: u32 = 0x7F50_4B47;

/// Size (in bytes) of the base PKG header (`0x00`–`0xBF`).
pub const PKG_HEADER_SIZE: usize = 0xC0;

/// Size of one file entry record in the item table.
pub const PKG_FILE_ENTRY_SIZE: usize = 0x20;

/// Well-known PS3 AES-128 key used for retail PKG data decryption.
pub const PS3_AES_KEY: [u8; 16] = [
    0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E, 0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8,
];

/// Well-known PSP AES-128 key used for PSP-type PKG data decryption.
pub const PSP_AES_KEY: [u8; 16] = [
    0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B,
];

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Release type field at offset `0x04`.
///
/// Determines the encryption scheme used for the data area:
/// - [`Debug`](PkgReleaseType::Debug) → SHA-1-based stream cipher
/// - [`Release`](PkgReleaseType::Release) → AES-128-ECB-CTR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PkgReleaseType {
    /// Debug package — data encrypted with SHA-1 stream cipher.
    Debug = 0x0001,
    /// Release/retail package — data encrypted with AES-128-CTR.
    Release = 0x0002,
}

impl TryFrom<u16> for PkgReleaseType {
    type Error = u16;
    fn try_from(v: u16) -> Result<Self, u16> {
        match v {
            0x0001 => Ok(Self::Debug),
            0x0002 => Ok(Self::Release),
            other => Err(other),
        }
    }
}

impl fmt::Display for PkgReleaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkgReleaseType::Debug => write!(f, "Debug"),
            PkgReleaseType::Release => write!(f, "Release"),
        }
    }
}

/// Platform type field at offset `0x06`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PkgPlatform {
    /// PS3 package.
    PS3 = 0x0001,
    /// PSP / PS Vita package.
    PSP = 0x0002,
}

impl TryFrom<u16> for PkgPlatform {
    type Error = u16;
    fn try_from(v: u16) -> Result<Self, u16> {
        match v {
            0x0001 => Ok(Self::PS3),
            0x0002 => Ok(Self::PSP),
            other => Err(other),
        }
    }
}

impl fmt::Display for PkgPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkgPlatform::PS3 => write!(f, "PS3"),
            PkgPlatform::PSP => write!(f, "PSP"),
        }
    }
}

/// Known DRM type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PkgDrmType {
    None = 0x0,
    Network = 0x1,
    Local = 0x2,
    Free = 0x3,
    PspGo = 0xD,
}

impl TryFrom<u32> for PkgDrmType {
    type Error = u32;
    fn try_from(v: u32) -> Result<Self, u32> {
        match v {
            0x0 => Ok(Self::None),
            0x1 => Ok(Self::Network),
            0x2 => Ok(Self::Local),
            0x3 => Ok(Self::Free),
            0xD => Ok(Self::PspGo),
            other => Err(other),
        }
    }
}

/// Known content type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PkgContentType {
    GameData = 0x04,
    GameExec = 0x05,
    Ps1Emu = 0x06,
    PspMinis = 0x07,
    SystemUpdate = 0x08,
    PspRemaster = 0x09,
    PspNeoGeo = 0x0A,
    Unk0B = 0x0B,
    Avatar = 0x0D,
    Minis2 = 0x0E,
    XmbPlugin = 0x0F,
    Theme = 0x12,
    DiscMovie = 0x13,
    Widget = 0x15,
    LicenseFile = 0x16,
    PspGo = 0x18,
}

impl TryFrom<u32> for PkgContentType {
    type Error = u32;
    fn try_from(v: u32) -> Result<Self, u32> {
        match v {
            0x04 => Ok(Self::GameData),
            0x05 => Ok(Self::GameExec),
            0x06 => Ok(Self::Ps1Emu),
            0x07 => Ok(Self::PspMinis),
            0x08 => Ok(Self::SystemUpdate),
            0x09 => Ok(Self::PspRemaster),
            0x0A => Ok(Self::PspNeoGeo),
            0x0B => Ok(Self::Unk0B),
            0x0D => Ok(Self::Avatar),
            0x0E => Ok(Self::Minis2),
            0x0F => Ok(Self::XmbPlugin),
            0x12 => Ok(Self::Theme),
            0x13 => Ok(Self::DiscMovie),
            0x15 => Ok(Self::Widget),
            0x16 => Ok(Self::LicenseFile),
            0x18 => Ok(Self::PspGo),
            other => Err(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Header structs
// ---------------------------------------------------------------------------

/// Main PKG header (`0x00`–`0xBF`, all big-endian).
///
/// ```text
/// 0x00  u32      magic (0x7F504B47)
/// 0x04  u16      release_type   (debug / release)
/// 0x06  u16      platform       (PS3 / PSP)
/// 0x08  u32      metadata_offset
/// 0x0C  u32      metadata_count
/// 0x10  u32      metadata_size
/// 0x14  u32      item_count
/// 0x18  u64      total_size
/// 0x20  u64      data_offset
/// 0x28  u64      data_size
/// 0x30  [u8;48]  content_id  (null-padded ASCII)
/// 0x60  [u8;16]  qa_digest   (SHA-1 key material for debug crypto)
/// 0x70  [u8;16]  klicensee   (AES-CTR initial counter)
/// 0x80  [u8;64]  header_digest
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgHeader {
    pub magic: u32,
    pub release_type: u16,
    pub platform: u16,
    pub metadata_offset: u32,
    pub metadata_count: u32,
    pub metadata_size: u32,
    pub item_count: u32,
    pub total_size: u64,
    pub data_offset: u64,
    pub data_size: u64,
    pub content_id: [u8; 48],
    pub qa_digest: [u8; 16],
    pub klicensee: [u8; 16],
    pub header_digest: [u8; 64],
}

impl PkgHeader {
    /// Validates the magic field.
    #[inline]
    pub const fn is_valid_magic(&self) -> bool {
        self.magic == PKG_MAGIC
    }

    /// Content-ID as a UTF-8 `&str`, stripping trailing NULs.
    pub fn content_id_str(&self) -> &str {
        let end = self
            .content_id
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.content_id.len());
        core::str::from_utf8(&self.content_id[..end]).unwrap_or("<invalid UTF-8>")
    }

    /// Attempt to interpret the raw `release_type` field as [`PkgReleaseType`].
    pub fn release_type_enum(&self) -> Result<PkgReleaseType, u16> {
        PkgReleaseType::try_from(self.release_type)
    }

    /// Attempt to interpret the raw `platform` field as [`PkgPlatform`].
    pub fn platform_enum(&self) -> Result<PkgPlatform, u16> {
        PkgPlatform::try_from(self.platform)
    }
}

impl fmt::Display for PkgHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PkgHeader(release={:#06x}, platform={:#06x}, content_id=\"{}\", items={}, \
             total_size={}, data_offset={:#x}, data_size={})",
            self.release_type,
            self.platform,
            self.content_id_str(),
            self.item_count,
            self.total_size,
            self.data_offset,
            self.data_size,
        )
    }
}

// ---------------------------------------------------------------------------

/// Extended header fields at various fixed offsets past the main header.
///
/// ```text
/// 0xB0  u32       drm_type
/// 0xB4  u32       content_type
/// 0xB8  u16       package_type
/// 0xBA  u16       package_flag
/// 0xBC  u16       make_package_npdrm_revision
/// 0xBE  u16       package_version
/// 0xC0  [u8;4]    (padding)
/// 0xC4  [u8;9]    title_id  (null-padded ASCII)
/// 0xCD  [u8;16]   qa_digest
/// 0xDD  [u8;7]    (padding)
/// 0xE4  u32       system_version
/// 0xE8  u32       app_version
/// 0xEC  [u8;4]    (padding)
/// 0xF0  [u8;32]   install_directory  (null-padded ASCII)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgExtendedHeader {
    pub drm_type: u32,
    pub content_type: u32,
    pub package_type: u16,
    pub package_flag: u16,
    pub npdrm_revision: u16,
    pub package_version: u16,
    pub title_id: [u8; 9],
    pub qa_digest: [u8; 16],
    pub system_version: u32,
    pub app_version: u32,
    pub install_directory: [u8; 32],
}

impl PkgExtendedHeader {
    /// Title-ID as a `&str`, stripping trailing NULs.
    pub fn title_id_str(&self) -> &str {
        let end = self
            .title_id
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.title_id.len());
        core::str::from_utf8(&self.title_id[..end]).unwrap_or("<invalid UTF-8>")
    }

    /// Install directory as a `&str`, stripping trailing NULs.
    pub fn install_directory_str(&self) -> &str {
        let end = self
            .install_directory
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.install_directory.len());
        core::str::from_utf8(&self.install_directory[..end]).unwrap_or("<invalid UTF-8>")
    }

    /// Attempt to interpret the raw `drm_type` as [`PkgDrmType`].
    pub fn drm_type_enum(&self) -> Result<PkgDrmType, u32> {
        PkgDrmType::try_from(self.drm_type)
    }

    /// Attempt to interpret the raw `content_type` as [`PkgContentType`].
    pub fn content_type_enum(&self) -> Result<PkgContentType, u32> {
        PkgContentType::try_from(self.content_type)
    }
}

impl fmt::Display for PkgExtendedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PkgExtendedHeader(title_id=\"{}\", drm={:#x}, content={:#x}, \
             pkg_ver={:#06x}, sys_ver={:#010x}, install_dir=\"{}\")",
            self.title_id_str(),
            self.drm_type,
            self.content_type,
            self.package_version,
            self.system_version,
            self.install_directory_str(),
        )
    }
}

// ---------------------------------------------------------------------------
// File-entry struct
// ---------------------------------------------------------------------------

/// A single entry in the PKG item table (32 bytes each).
///
/// ```text
/// 0x00  u32  name_offset   (relative to data_offset)
/// 0x04  u32  name_size
/// 0x08  u64  data_offset   (relative to PKG data_offset)
/// 0x10  u64  data_size
/// 0x18  u32  flags         (content_type MSB | file_type LSB)
/// 0x1C  u32  padding
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkgFileEntry {
    pub name_offset: u32,
    pub name_size: u32,
    pub data_offset: u64,
    pub data_size: u64,
    pub flags: u32,
    pub padding: u32,
}

impl PkgFileEntry {
    /// The content-type byte (MSB of `flags`).
    #[inline]
    pub const fn content_type(&self) -> u8 {
        (self.flags >> 24) as u8
    }

    /// The file-type byte (LSB of `flags`).
    #[inline]
    pub const fn file_type(&self) -> u8 {
        (self.flags & 0xFF) as u8
    }

    /// Whether this entry is a PSP-type entry (`content_type == 0x90`).
    #[inline]
    pub const fn is_psp(&self) -> bool {
        self.content_type() == 0x90
    }

    /// A directory entry has `file_type == 0x04` and `data_size == 0`.
    #[inline]
    pub const fn is_directory(&self) -> bool {
        self.file_type() == 0x04 && self.data_size == 0
    }
}

impl fmt::Display for PkgFileEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PkgEntry(name_off={:#x}, name_sz={}, data_off={:#x}, \
             data_sz={}, flags={:#010x})",
            self.name_offset, self.name_size, self.data_offset, self.data_size, self.flags,
        )
    }
}

// ---------------------------------------------------------------------------
// Resolved entry (with decoded name)
// ---------------------------------------------------------------------------

/// A fully-resolved file entry with its decoded name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgItem {
    /// Index of this item in the table.
    pub index: u32,
    /// Decoded file/directory name.
    pub name: String,
    /// Raw entry from the item table.
    pub entry: PkgFileEntry,
}

impl fmt::Display for PkgItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.entry.is_directory() {
            "dir"
        } else {
            "file"
        };
        write!(
            f,
            "PkgItem(#{}, \"{}\", {}, size={})",
            self.index, self.name, kind, self.entry.data_size,
        )
    }
}
