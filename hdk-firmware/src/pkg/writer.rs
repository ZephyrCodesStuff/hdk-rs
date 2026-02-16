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

    #[error("PKG is missing PARAM.SFO. 2014 PS3 hardware requires this file for installation")]
    MissingParamSfo,
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
    /// Overwrite-allowed flag — RPCS3 skips files without this bit
    /// if they already exist on disk.
    ///
    /// TODO: make this configurable
    const OVERWRITE: u32 = 0x8000_0000;

    /// Create a new raw-data file item (file_type = 0x03).
    const fn file(name: String, data: Vec<u8>) -> Self {
        Self {
            name,
            data,
            flags: Self::OVERWRITE | 0x03, // overwrite + raw data
        }
    }

    /// Create a new NPDRM SELF file item (file_type = 0x01).
    const fn self_file(name: String, data: Vec<u8>) -> Self {
        Self {
            name,
            data,
            flags: Self::OVERWRITE | 0x01, // overwrite + SELF
        }
    }

    /// Create a new directory item (file_type = 0x04).
    const fn directory(name: String) -> Self {
        Self {
            name,
            data: Vec::new(),
            flags: Self::OVERWRITE | 0x04, // overwrite + directory
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

    // Metadata fields (written as TLV packets in the metadata section)
    drm_type: u32,
    content_type: u32,
    package_type: u32,
    npdrm_revision: u16,
    package_version: u16,
    title_id: String,
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
            package_type: 0x4E, // TODO: https://www.psdevwiki.com/ps3/PKG_files#PackageType
            npdrm_revision: 0x1732,
            package_version: 0x0100,
            title_id: "XXXX00000".to_string(),
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

    /// Set the QA digest manually, overriding automatic computation.
    ///
    /// By default (`[0u8; 16]`), the writer computes the QA digest
    /// automatically as `SHA-1(plaintext_data_area)[0..16]`.
    /// Setting a non-zero value here bypasses that computation.
    pub const fn qa_digest(mut self, digest: [u8; 16]) -> Self {
        self.qa_digest = digest;
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

    /// Set the package type.
    pub const fn package_type(mut self, pt: u32) -> Self {
        self.package_type = pt;
        self
    }

    /// Set the title ID (max 9 bytes, will be NUL-padded).
    pub fn title_id(mut self, id: &str) -> Self {
        self.title_id = id.to_string();
        self
    }

    /// Set the install directory (max 32 bytes, will be NUL-padded).
    pub fn install_directory(mut self, dir: &str) -> Self {
        self.install_directory = dir.to_string();
        self
    }

    // -- Item addition ------------------------------------------------------

    /// Add a file to the package.
    pub fn add_file(&mut self, name: &str, data: Vec<u8>) {
        self.items.push(BuilderItem::file(name.to_string(), data));
    }

    /// Add a SELF file to the package (for NPDRM content).
    pub fn add_self_file(&mut self, name: &str, data: Vec<u8>) {
        self.items
            .push(BuilderItem::self_file(name.to_string(), data));
    }

    /// Add a directory to the package.
    pub fn add_directory(&mut self, name: &str) {
        self.items.push(BuilderItem::directory(name.to_string()));
    }

    /// Add a PSP-type file to the package.
    pub fn add_psp_file(&mut self, name: &str, data: Vec<u8>) {
        self.items
            .push(BuilderItem::file(name.to_string(), data).with_psp_flag());
    }

    // -- Writing ------------------------------------------------------------

    /// Write the complete PKG to the provided writer.
    ///
    /// This method consumes the builder and writes:
    /// 1. Main header (0x00–0xBF)
    /// 2. Metadata section (TLV packets starting at 0xC0)
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

        // Warn if PARAM.SFO is missing (required by PS3 hardware)
        if !self.items.iter().any(|i| i.name == "PARAM.SFO") {
            eprintln!(
                "warning: PKG is missing PARAM.SFO — PS3 hardware requires this file for installation"
            );
        }

        // Build metadata with placeholder total_size to determine its size
        let (placeholder_meta, metadata_count) = self.build_metadata(0, &self.qa_digest);
        let metadata_offset = PKG_HEADER_SIZE as u32; // 0xC0
        let metadata_size = placeholder_meta.len() as u32;

        // Calculate data_offset dynamically (16-byte aligned after metadata)
        let data_offset = ((metadata_offset as u64 + metadata_size as u64) + 15) & !15;

        // Calculate data area layout
        let item_count = self.items.len() as u32;
        let entry_table_size = (item_count as usize) * PKG_FILE_ENTRY_SIZE;

        // Layout: [entry_table][names...][file_data...]
        let mut name_offsets = Vec::with_capacity(item_count as usize);
        let mut data_offsets = Vec::with_capacity(item_count as usize);

        let mut current_offset = entry_table_size;

        // Allocate space for names (each padded to 16-byte boundary).
        // RPCS3's decrypt() does not handle sub-block alignment, so every
        // name offset must be 16-byte aligned.
        for item in &self.items {
            name_offsets.push(current_offset as u32);
            let name_alloc = (item.name.len() + 1 + 15) & !15; // +1 NUL, align to 16
            current_offset = current_offset
                .checked_add(name_alloc)
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

        // Rebuild metadata with the correct total_size
        let (meta_buf, _) = self.build_metadata(total_size, &self.qa_digest);

        // Build the main header (placeholder — will rewrite after computing qa_digest)
        let mut header = PkgHeader {
            magic: PKG_MAGIC,
            release_type: self.release_type,
            platform: self.platform,
            metadata_offset,
            metadata_count,
            metadata_size,
            item_count,
            total_size,
            data_offset,
            data_size,
            content_id: Self::pad_bytes::<48>(self.content_id.as_bytes()),
            qa_digest: self.qa_digest,
            klicensee: self.klicensee,
            header_digest: [0; 64],
        };

        // Write main header (0x00–0xBF) — will rewrite after computing qa_digest
        Self::write_header(&mut writer, &header)?;

        // Write metadata section (0xC0+) — will rewrite after computing qa_digest
        writer.seek(SeekFrom::Start(metadata_offset as u64))?;
        writer.write_all(&meta_buf)?;

        // Zero-fill the alignment gap between metadata end and data_offset
        let meta_end = metadata_offset as u64 + meta_buf.len() as u64;
        if data_offset > meta_end {
            let gap = (data_offset - meta_end) as usize;
            writer.write_all(&vec![0u8; gap])?;
        }

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

        // Compute QA digest from plaintext if not manually set
        let qa_digest = if self.qa_digest == [0u8; 16] {
            let sha = Sha1::from(&plaintext).digest().bytes(); // [u8; 20]
            let mut digest = [0u8; 16];
            digest.copy_from_slice(&sha[..16]);
            digest
        } else {
            self.qa_digest
        };

        // Update header and metadata with the final digest, then rewrite them
        header.qa_digest = qa_digest;
        let (meta_buf, _) = self.build_metadata(total_size, &qa_digest);

        Self::write_header(&mut writer, &header)?;
        writer.seek(SeekFrom::Start(metadata_offset as u64))?;
        writer.write_all(&meta_buf)?;

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

    /// Pad a byte slice to a fixed length with NULs, but inserting the bytes at the start.
    fn pad_bytes_prefix<const N: usize>(src: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        let len = std::cmp::min(src.len(), N);
        out[N - len..].copy_from_slice(&src[..len]);
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

    /// Build the metadata section as a TLV binary blob.
    ///
    /// Returns the serialized metadata buffer and the number of packets.
    /// `total_size` is the total PKG file size (used for metadata ID 0x04).
    /// `qa_digest` is the 16-byte digest to embed in metadata packet 0x07.
    fn build_metadata(&self, total_size: u64, qa_digest: &[u8; 16]) -> (Vec<u8>, u32) {
        let mut buf = Vec::new();
        let mut count = 0u32;

        // 0x01: DRM Type
        Self::write_metadata_packet(
            &mut buf,
            metadata_id::DRM_TYPE,
            &self.drm_type.to_be_bytes(),
        );
        count += 1;

        // 0x02: Content Type
        Self::write_metadata_packet(
            &mut buf,
            metadata_id::CONTENT_TYPE,
            &self.content_type.to_be_bytes(),
        );
        count += 1;

        // 0x03: Package Type
        Self::write_metadata_packet(
            &mut buf,
            metadata_id::PACKAGE_TYPE,
            &self.package_type.to_be_bytes(),
        );
        count += 1;

        // 0x04: Package Size (total PKG file size)
        Self::write_metadata_packet(
            &mut buf,
            metadata_id::PACKAGE_SIZE,
            &total_size.to_be_bytes(),
        );
        count += 1;

        // 0x05: Make Pkg / NPDRM Revision (4 bytes, only data)
        let mut rev = [0u8; 4];
        rev[0..2].copy_from_slice(&self.npdrm_revision.to_be_bytes());
        rev[2..4].copy_from_slice(&self.package_version.to_be_bytes());
        Self::write_metadata_packet(&mut buf, metadata_id::MAKE_PKG_REV, &rev);
        count += 1;

        // 0x06: Title ID (must be 12 bytes, NUL-padded)
        Self::write_metadata_packet(
            &mut buf,
            metadata_id::TITLE_ID,
            &Self::pad_bytes::<12>(self.title_id.as_bytes()),
        );
        count += 1;

        // 0x07: QA Digest (must be 24 bytes, zero-padded)
        Self::write_metadata_packet(
            &mut buf,
            metadata_id::QA_DIGEST,
            &Self::pad_bytes_prefix::<24>(qa_digest),
        );
        count += 1;

        // 0x0A: Install Directory (8-byte prefix + directory name)
        let mut install_buf = vec![0u8; 8 + self.install_directory.len()];
        install_buf[8..].copy_from_slice(self.install_directory.as_bytes());
        Self::write_metadata_packet(&mut buf, metadata_id::INSTALL_DIR, &install_buf);
        count += 1;

        (buf, count)
    }

    /// Write a single TLV metadata packet to a buffer.
    fn write_metadata_packet(buf: &mut Vec<u8>, id: u32, data: &[u8]) {
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
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
        let mut pkg = PkgBuilder::new()
            .release_type(PkgReleaseType::Debug)
            .platform(PkgPlatform::PS3)
            .content_id("UP0001-TEST00001_00-0000000000000000")
            .title_id("TEST00001")
            .qa_digest(qa);

        pkg.add_directory("USRDIR");
        pkg.add_file("USRDIR/hello.txt", b"Hello, PKG!".to_vec());

        pkg.write(io::Cursor::new(&mut buf)).unwrap();

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
        let mut pkg = PkgBuilder::new()
            .release_type(PkgReleaseType::Release)
            .platform(PkgPlatform::PS3)
            .content_id("UP0001-TEST00002_00-0000000000000000")
            .title_id("TEST00002")
            .klicensee(klic);

        pkg.add_file("EBOOT.BIN", vec![0x42; 64]);
        pkg.write(io::Cursor::new(&mut buf)).unwrap();

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
        let mut pkg = PkgBuilder::new();

        pkg.add_directory("data");
        pkg.add_file("data/file1.txt", b"content1".to_vec());
        pkg.add_file("data/file2.bin", vec![1, 2, 3, 4]);
        pkg.add_directory("docs");
        pkg.add_file("docs/readme.txt", b"Read me!".to_vec());

        pkg.write(io::Cursor::new(&mut buf)).unwrap();

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
