//! PS3 PKG writer.
//!
//! Constructs PKG archives with proper header generation and on-the-fly
//! encryption for **both** debug and retail packages.
//!
//! Debug packages use a SHA-1-based stream cipher keyed on `qa_digest`.
//! Retail packages use AES-128-ECB-CTR keyed on the well-known PS3/PSP key
//! with `klicensee` as the initial counter value.
//!
//! # Example
//!
//! ```ignore
//! use hdk_firmware::pkg::{PkgBuilder, PkgPlatform, PkgReleaseType};
//!
//! let pkg = PkgBuilder::new()
//!     .release_type(PkgReleaseType::Debug)
//!     .platform(PkgPlatform::PS3)
//!     .content_id("UP0001-TEST00001_00-0000000000000000")
//!     .title_id("TEST00001")
//!     .add_directory("USRDIR")
//!     .add_file("USRDIR/EBOOT.BIN", eboot_data)
//!     .write(output_file)?;
//! ```

use std::io::{self, Seek, SeekFrom, Write};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Block};
use byteorder::{BigEndian, WriteBytesExt};
use sha1_smol::Sha1;
use thiserror::Error;

use super::structs::*;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PkgWriteError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("content ID \"{0}\" exceeds 48 bytes")]
    ContentIdTooLong(String),

    #[error("title ID \"{0}\" exceeds 9 bytes")]
    TitleIdTooLong(String),

    #[error("install directory \"{0}\" exceeds 32 bytes")]
    InstallDirTooLong(String),

    #[error("entry name \"{0}\" exceeds 255 bytes")]
    EntryNameTooLong(String),

    #[error("data area size exceeds u64::MAX")]
    DataOverflow,
}

// ---------------------------------------------------------------------------
// Builder Item
// ---------------------------------------------------------------------------

/// An item (file or directory) to be written to the PKG.
#[derive(Debug, Clone)]
struct BuilderItem {
    name: String,
    data: Vec<u8>,
    flags: u32,
}

impl BuilderItem {
    /// Create a new file item.
    const fn file(name: String, data: Vec<u8>) -> Self {
        Self {
            name,
            data,
            flags: 0x00_00_00_01, // file_type = 0x01
        }
    }

    /// Create a new directory item.
    const fn directory(name: String) -> Self {
        Self {
            name,
            data: Vec::new(),
            flags: 0x00_00_00_04, // file_type = 0x04
        }
    }

    /// Mark this item as a PSP-type entry (content_type = 0x90).
    const fn with_psp_flag(mut self) -> Self {
        self.flags |= 0x90_00_00_00;
        self
    }

    const fn is_directory(&self) -> bool {
        (self.flags & 0xFF) == 0x04
    }
}

// ---------------------------------------------------------------------------
// PKG Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a PS3/PSP PKG archive.
///
/// Uses the builder pattern to configure all header fields and add items,
/// then writes the complete PKG with proper encryption.
#[derive(Debug, Clone)]
pub struct PkgBuilder {
    // Main header fields
    release_type: u16,
    platform: u16,
    content_id: String,
    qa_digest: [u8; 16],
    klicensee: [u8; 16],

    // Extended header fields
    drm_type: u32,
    content_type: u32,
    package_type: u16,
    package_flag: u16,
    npdrm_revision: u16,
    package_version: u16,
    title_id: String,
    ext_qa_digest: [u8; 16],
    system_version: u32,
    app_version: u32,
    install_directory: String,

    // Items
    items: Vec<BuilderItem>,
}

impl Default for PkgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PkgBuilder {
    /// Create a new PKG builder with sensible defaults.
    ///
    /// Default configuration:
    /// - Release type: Debug
    /// - Platform: PS3
    /// - Content ID: "UP0000-XXXX00000_00-0000000000000000"
    /// - Title ID: "XXXX00000"
    /// - All digests/keys zeroed
    pub fn new() -> Self {
        Self {
            release_type: PkgReleaseType::Debug as u16,
            platform: PkgPlatform::PS3 as u16,
            content_id: "UP0000-XXXX00000_00-0000000000000000".to_string(),
            qa_digest: [0u8; 16],
            klicensee: [0u8; 16],

            drm_type: PkgDrmType::Free as u32,
            content_type: PkgContentType::GameData as u32,
            package_type: 0,
            package_flag: 0,
            npdrm_revision: 0,
            package_version: 0,
            title_id: "XXXX00000".to_string(),
            ext_qa_digest: [0u8; 16],
            system_version: 0,
            app_version: 0,
            install_directory: "XXXX00000".to_string(),

            items: Vec::new(),
        }
    }

    // -- Configuration methods ----------------------------------------------

    /// Set the release type (debug or retail).
    ///
    /// Retail packages have the high bit (0x8000) set in the release_type field,
    /// while debug packages do not.
    pub const fn release_type(mut self, rt: PkgReleaseType) -> Self {
        self.release_type = match rt {
            PkgReleaseType::Debug => rt as u16,
            PkgReleaseType::Release => (rt as u16) | 0x8000,
        };
        self
    }

    /// Set the platform (PS3 or PSP).
    pub const fn platform(mut self, p: PkgPlatform) -> Self {
        self.platform = p as u16;
        self
    }

    /// Set the content ID (max 48 bytes, will be NUL-padded).
    pub fn content_id(mut self, id: &str) -> Self {
        self.content_id = id.to_string();
        self
    }

    /// Set the QA digest (used as key material for debug encryption).
    pub const fn qa_digest(mut self, digest: [u8; 16]) -> Self {
        self.qa_digest = digest;
        self.ext_qa_digest = digest; // Keep both in sync by default
        self
    }

    /// Set the klicensee (AES-CTR initial counter for retail encryption).
    pub const fn klicensee(mut self, klic: [u8; 16]) -> Self {
        self.klicensee = klic;
        self
    }

    /// Set the DRM type.
    pub const fn drm_type(mut self, drm: PkgDrmType) -> Self {
        self.drm_type = drm as u32;
        self
    }

    /// Set the content type.
    pub const fn content_type(mut self, ct: PkgContentType) -> Self {
        self.content_type = ct as u32;
        self
    }

    /// Set the package version.
    pub const fn package_version(mut self, ver: u16) -> Self {
        self.package_version = ver;
        self
    }

    /// Set the title ID (max 9 bytes, will be NUL-padded).
    pub fn title_id(mut self, id: &str) -> Self {
        self.title_id = id.to_string();
        self
    }

    /// Set the system version.
    pub const fn system_version(mut self, ver: u32) -> Self {
        self.system_version = ver;
        self
    }

    /// Set the app version.
    pub const fn app_version(mut self, ver: u32) -> Self {
        self.app_version = ver;
        self
    }

    /// Set the install directory (max 32 bytes, will be NUL-padded).
    pub fn install_directory(mut self, dir: &str) -> Self {
        self.install_directory = dir.to_string();
        self
    }

    // -- Item addition ------------------------------------------------------

    /// Add a file to the package.
    pub fn add_file(mut self, name: &str, data: Vec<u8>) -> Self {
        self.items.push(BuilderItem::file(name.to_string(), data));
        self
    }

    /// Add a directory to the package.
    pub fn add_directory(mut self, name: &str) -> Self {
        self.items.push(BuilderItem::directory(name.to_string()));
        self
    }

    /// Add a PSP-type file to the package.
    pub fn add_psp_file(mut self, name: &str, data: Vec<u8>) -> Self {
        self.items
            .push(BuilderItem::file(name.to_string(), data).with_psp_flag());
        self
    }

    // -- Writing ------------------------------------------------------------

    /// Write the complete PKG to the provided writer.
    ///
    /// This method consumes the builder and writes:
    /// 1. Main header (0x00–0xBF)
    /// 2. Extended header (0xB0–0x10F)
    /// 3. Encrypted data area (item table + names + file data)
    pub fn write<W: Write + Seek>(self, mut writer: W) -> Result<(), PkgWriteError> {
        // Validate fields
        if self.content_id.len() > 48 {
            return Err(PkgWriteError::ContentIdTooLong(self.content_id));
        }
        if self.title_id.len() > 9 {
            return Err(PkgWriteError::TitleIdTooLong(self.title_id));
        }
        if self.install_directory.len() > 32 {
            return Err(PkgWriteError::InstallDirTooLong(self.install_directory));
        }
        for item in &self.items {
            if item.name.len() > 255 {
                return Err(PkgWriteError::EntryNameTooLong(item.name.clone()));
            }
        }

        // Calculate data area layout
        let data_offset: u64 = 0x0110; // Standard offset after headers
        let item_count = self.items.len() as u32;
        let entry_table_size = (item_count as usize) * PKG_FILE_ENTRY_SIZE;

        // Layout: [entry_table][names...][file_data...]
        let mut name_offsets = Vec::with_capacity(item_count as usize);
        let mut data_offsets = Vec::with_capacity(item_count as usize);

        let mut current_offset = entry_table_size;

        // Allocate space for names
        for item in &self.items {
            name_offsets.push(current_offset as u32);
            current_offset = current_offset
                .checked_add(item.name.len() + 1) // +1 for NUL terminator
                .ok_or(PkgWriteError::DataOverflow)?;
        }

        // Allocate space for file data (16-byte aligned)
        for item in &self.items {
            if !item.is_directory() {
                // Align to 16-byte boundary
                current_offset = (current_offset + 15) & !15;
                data_offsets.push(current_offset as u64);
                current_offset = current_offset
                    .checked_add(item.data.len())
                    .ok_or(PkgWriteError::DataOverflow)?;
            } else {
                data_offsets.push(0);
            }
        }

        // Pad the entire data area to 16-byte boundary for block-aligned encryption
        current_offset = (current_offset + 15) & !15;

        let data_size = current_offset as u64;
        let total_size = data_offset + data_size;

        // Build the main header
        let header = PkgHeader {
            magic: PKG_MAGIC,
            release_type: self.release_type,
            platform: self.platform,
            metadata_offset: 0,
            metadata_count: 0,
            metadata_size: 0,
            item_count,
            total_size,
            data_offset,
            data_size,
            content_id: Self::pad_bytes::<48>(self.content_id.as_bytes()),
            qa_digest: self.qa_digest,
            klicensee: self.klicensee,
            header_digest: [0u8; 64], // Could compute SHA-256, but often zero
        };

        // Build the extended header
        let ext_header = PkgExtendedHeader {
            drm_type: self.drm_type,
            content_type: self.content_type,
            package_type: self.package_type,
            package_flag: self.package_flag,
            npdrm_revision: self.npdrm_revision,
            package_version: self.package_version,
            title_id: Self::pad_bytes::<9>(self.title_id.as_bytes()),
            qa_digest: self.ext_qa_digest,
            system_version: self.system_version,
            app_version: self.app_version,
            install_directory: Self::pad_bytes::<32>(self.install_directory.as_bytes()),
        };

        // Write headers
        Self::write_header(&mut writer, &header)?;
        Self::write_ext_header(&mut writer, &ext_header)?;

        // Prepare plaintext data area
        let mut plaintext = vec![0u8; data_size as usize];
        {
            let mut cursor = io::Cursor::new(&mut plaintext[..]);

            // Write entry table
            for (i, item) in self.items.iter().enumerate() {
                cursor.write_u32::<BigEndian>(name_offsets[i])?;
                cursor.write_u32::<BigEndian>((item.name.len() + 1) as u32)?;
                cursor.write_u64::<BigEndian>(data_offsets[i])?;
                cursor.write_u64::<BigEndian>(item.data.len() as u64)?;
                cursor.write_u32::<BigEndian>(item.flags)?;
                cursor.write_u32::<BigEndian>(0)?; // padding
            }

            // Write names
            for (i, item) in self.items.iter().enumerate() {
                cursor.seek(SeekFrom::Start(name_offsets[i] as u64))?;
                cursor.write_all(item.name.as_bytes())?;
                cursor.write_u8(0)?; // NUL terminator
            }

            // Write file data
            for (i, item) in self.items.iter().enumerate() {
                if !item.is_directory() {
                    cursor.seek(SeekFrom::Start(data_offsets[i]))?;
                    cursor.write_all(&item.data)?;
                }
            }
        }

        // Encrypt the data area
        Self::encrypt_data(
            &mut plaintext,
            &header,
            if self.platform == PkgPlatform::PSP as u16 {
                &PSP_AES_KEY
            } else {
                &PS3_AES_KEY
            },
        );

        // Write encrypted data area
        writer.seek(SeekFrom::Start(data_offset))?;
        writer.write_all(&plaintext)?;

        Ok(())
    }

    // -- Internal helpers ---------------------------------------------------

    /// Pad a byte slice to a fixed length with NULs.
    fn pad_bytes<const N: usize>(src: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        let len = std::cmp::min(src.len(), N);
        out[..len].copy_from_slice(&src[..len]);
        out
    }

    /// Write the main header to the writer.
    fn write_header<W: Write + Seek>(w: &mut W, h: &PkgHeader) -> io::Result<()> {
        w.seek(SeekFrom::Start(0))?;
        w.write_u32::<BigEndian>(h.magic)?;
        w.write_u16::<BigEndian>(h.release_type)?;
        w.write_u16::<BigEndian>(h.platform)?;
        w.write_u32::<BigEndian>(h.metadata_offset)?;
        w.write_u32::<BigEndian>(h.metadata_count)?;
        w.write_u32::<BigEndian>(h.metadata_size)?;
        w.write_u32::<BigEndian>(h.item_count)?;
        w.write_u64::<BigEndian>(h.total_size)?;
        w.write_u64::<BigEndian>(h.data_offset)?;
        w.write_u64::<BigEndian>(h.data_size)?;
        w.write_all(&h.content_id)?;
        w.write_all(&h.qa_digest)?;
        w.write_all(&h.klicensee)?;
        w.write_all(&h.header_digest)?;
        Ok(())
    }

    /// Write the extended header to the writer.
    fn write_ext_header<W: Write + Seek>(w: &mut W, eh: &PkgExtendedHeader) -> io::Result<()> {
        w.seek(SeekFrom::Start(0xB0))?;
        w.write_u32::<BigEndian>(eh.drm_type)?;
        w.write_u32::<BigEndian>(eh.content_type)?;
        w.write_u16::<BigEndian>(eh.package_type)?;
        w.write_u16::<BigEndian>(eh.package_flag)?;
        w.write_u16::<BigEndian>(eh.npdrm_revision)?;
        w.write_u16::<BigEndian>(eh.package_version)?;

        // Padding + title_id at 0xC4
        w.seek(SeekFrom::Start(0xC4))?;
        w.write_all(&eh.title_id)?;
        w.write_all(&eh.qa_digest)?;

        // System/app version at 0xE4
        w.seek(SeekFrom::Start(0xE4))?;
        w.write_u32::<BigEndian>(eh.system_version)?;
        w.write_u32::<BigEndian>(eh.app_version)?;

        // Install directory at 0xF0
        w.seek(SeekFrom::Start(0xF0))?;
        w.write_all(&eh.install_directory)?;

        Ok(())
    }

    /// Encrypt the data area in-place based on the release type.
    fn encrypt_data(data: &mut [u8], header: &PkgHeader, aes_key: &[u8; 16]) {
        if data.is_empty() {
            return;
        }

        if header.release_type & 0x8000 != 0 {
            // Retail / finalized (AES-128-ECB-CTR)
            Self::encrypt_retail(data, header, aes_key);
        } else {
            // Debug (SHA-1 stream cipher)
            Self::encrypt_debug(data, header);
        }
    }

    /// Debug encryption: SHA-1-based stream cipher keyed on `qa_digest`.
    ///
    /// Since XOR is its own inverse, the encryption algorithm is identical
    /// to decryption.
    fn encrypt_debug(data: &mut [u8], header: &PkgHeader) {
        let qa = &header.qa_digest;

        // Pre-build the 64-byte SHA-1 input template
        let mut sha_input = [0u8; 64];
        sha_input[0..8].copy_from_slice(&qa[0..8]);
        sha_input[8..16].copy_from_slice(&qa[0..8]);
        sha_input[16..24].copy_from_slice(&qa[8..16]);
        sha_input[24..32].copy_from_slice(&qa[8..16]);

        let blocks = data.len().div_ceil(16);
        for i in 0..blocks {
            let block_idx = i as u64;
            sha_input[56..64].copy_from_slice(&block_idx.to_be_bytes());
            let hash = Sha1::from(sha_input).digest().bytes();

            let start = i * 16;
            let end = std::cmp::min(start + 16, data.len());
            for j in start..end {
                data[j] ^= hash[j - start];
            }
        }
    }

    /// Retail encryption: AES-128-ECB-CTR with `klicensee` as initial counter.
    ///
    /// Since XOR is its own inverse, the encryption algorithm is identical
    /// to decryption.
    fn encrypt_retail(data: &mut [u8], header: &PkgHeader, aes_key: &[u8; 16]) {
        let cipher = Aes128::new(aes_key.into());
        let klicensee = u128::from_be_bytes(header.klicensee);

        let blocks = data.len().div_ceil(16);
        for i in 0..blocks {
            let ctr = klicensee.wrapping_add(i as u128);
            let mut block = Block::clone_from_slice(&ctr.to_be_bytes());
            cipher.encrypt_block(&mut block);

            let start = i * 16;
            let end = std::cmp::min(start + 16, data.len());
            for j in start..end {
                data[j] ^= block[j - start];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::reader::PkgArchive;

    #[test]
    fn writes_debug_pkg_roundtrip() {
        let qa = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];

        let mut buf = Vec::new();
        PkgBuilder::new()
            .release_type(PkgReleaseType::Debug)
            .platform(PkgPlatform::PS3)
            .content_id("UP0001-TEST00001_00-0000000000000000")
            .title_id("TEST00001")
            .qa_digest(qa)
            .add_directory("USRDIR")
            .add_file("USRDIR/hello.txt", b"Hello, PKG!".to_vec())
            .write(io::Cursor::new(&mut buf))
            .unwrap();

        // Read it back
        let mut pkg = PkgArchive::open(io::Cursor::new(&buf)).unwrap();
        assert_eq!(pkg.item_count(), 2);
        assert!(pkg.is_debug());

        let items = pkg.read_items().unwrap();
        assert_eq!(items[0].name, "USRDIR");
        assert!(items[0].entry.is_directory());
        assert_eq!(items[1].name, "USRDIR/hello.txt");

        let data = pkg.read_item_data(1).unwrap();
        assert_eq!(data, b"Hello, PKG!");
    }

    #[test]
    fn writes_retail_pkg_roundtrip() {
        let klic = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        let mut buf = Vec::new();
        PkgBuilder::new()
            .release_type(PkgReleaseType::Release)
            .platform(PkgPlatform::PS3)
            .content_id("UP0001-TEST00002_00-0000000000000000")
            .title_id("TEST00002")
            .klicensee(klic)
            .add_file("EBOOT.BIN", vec![0x42; 64])
            .write(io::Cursor::new(&mut buf))
            .unwrap();

        // Read it back
        let mut pkg = PkgArchive::open(io::Cursor::new(&buf)).unwrap();
        assert_eq!(pkg.item_count(), 1);
        assert!(pkg.is_retail());

        let items = pkg.read_items().unwrap();
        assert_eq!(items[0].name, "EBOOT.BIN");

        let data = pkg.read_item_data(0).unwrap();
        assert_eq!(data, vec![0x42; 64]);
    }

    #[test]
    fn handles_multiple_files() {
        let mut buf = Vec::new();
        PkgBuilder::new()
            .add_directory("data")
            .add_file("data/file1.txt", b"content1".to_vec())
            .add_file("data/file2.bin", vec![1, 2, 3, 4])
            .add_directory("docs")
            .add_file("docs/readme.txt", b"Read me!".to_vec())
            .write(io::Cursor::new(&mut buf))
            .unwrap();

        let mut pkg = PkgArchive::open(io::Cursor::new(&buf)).unwrap();
        assert_eq!(pkg.item_count(), 5);

        let items = pkg.read_items().unwrap();
        assert_eq!(items[0].name, "data");
        assert_eq!(items[1].name, "data/file1.txt");
        assert_eq!(items[2].name, "data/file2.bin");
        assert_eq!(items[3].name, "docs");
        assert_eq!(items[4].name, "docs/readme.txt");

        let data1 = pkg.read_item_data(1).unwrap();
        assert_eq!(data1, b"content1");

        let data2 = pkg.read_item_data(2).unwrap();
        assert_eq!(data2, vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_content_id_too_long() {
        let long_id = "X".repeat(49);
        let result = PkgBuilder::new()
            .content_id(&long_id)
            .write(io::Cursor::new(&mut Vec::new()));

        assert!(matches!(result, Err(PkgWriteError::ContentIdTooLong(_))));
    }

    #[test]
    fn rejects_title_id_too_long() {
        let long_id = "X".repeat(10);
        let result = PkgBuilder::new()
            .title_id(&long_id)
            .write(io::Cursor::new(&mut Vec::new()));

        assert!(matches!(result, Err(PkgWriteError::TitleIdTooLong(_))));
    }
}
