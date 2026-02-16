//! PS3 PKG reader.
//!
//! Parses the header, extended header, and the data area (entries, names,
//! file data) with on-the-fly decryption for **both** debug and retail PKGs.
//!
//! Debug packages use a SHA-1-based stream cipher keyed on `qa_digest`.
//! Retail packages use AES-128-ECB-CTR keyed on the well-known PS3/PSP key
//! with `klicensee` as the initial counter value.

use std::io::{self, Read, Seek, SeekFrom};

use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
use aes::{Aes128, Block};
use byteorder::{BigEndian, ReadBytesExt};
use sha1_smol::Sha1;
use thiserror::Error;

use super::structs::*;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PkgError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid PKG magic (expected 0x7F504B47)")]
    InvalidMagic,

    #[error("PKG file too small for header")]
    FileTooSmall,

    #[error("data_offset + data_size exceeds file size")]
    DataOutOfBounds,

    #[error("item_count is zero")]
    NoItems,

    #[error("item table exceeds data area")]
    ItemTableOverflow,

    #[error("entry index {0} out of range")]
    EntryIndex(usize),

    #[error("entry name or data offset out of bounds")]
    EntryOutOfBounds,

    #[error("unsupported release type {0:#06x} — cannot decrypt")]
    UnsupportedReleaseType(u16),

    #[error("invalid UTF-8 in entry name at index {0}")]
    InvalidEntryName(usize),
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Streaming PS3 PKG reader.
///
/// Data-area reads are decrypted transparently based on the release type
/// stored in the header — no separate decrypt step is needed.
///
/// ```ignore
/// let mut pkg = PkgArchive::open(file)?;
/// let items = pkg.read_items()?;
///
/// for item in &items {
///     println!("{item}");
/// }
///
/// let data = pkg.read_item_data(0)?;
/// ```
pub struct PkgArchive<R: Read + Seek> {
    inner: R,
    header: PkgHeader,
    ext_header: PkgExtendedHeader,
    file_size: u64,
    /// Default AES key selected from the platform field (PS3 or PSP).
    aes_key: [u8; 16],
}

impl<R: Read + Seek> PkgArchive<R> {
    /// Open a PKG and parse the header + extended header.
    ///
    /// This does **not** read the item table yet — call [`Self::read_items`]
    /// (or [`Self::read_item_data`]) for that.
    pub fn open(mut inner: R) -> Result<Self, PkgError> {
        let file_size = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;

        if file_size < PKG_HEADER_SIZE as u64 {
            return Err(PkgError::FileTooSmall);
        }

        // ---- main header (0x00) ----
        let magic = inner.read_u32::<BigEndian>()?;
        if magic != PKG_MAGIC {
            return Err(PkgError::InvalidMagic);
        }

        let release_type = inner.read_u16::<BigEndian>()?; // 0x04
        let platform = inner.read_u16::<BigEndian>()?; // 0x06
        let metadata_offset = inner.read_u32::<BigEndian>()?;
        let metadata_count = inner.read_u32::<BigEndian>()?;
        let metadata_size = inner.read_u32::<BigEndian>()?;
        let item_count = inner.read_u32::<BigEndian>()?;
        let total_size = inner.read_u64::<BigEndian>()?;
        let data_offset = inner.read_u64::<BigEndian>()?;
        let data_size = inner.read_u64::<BigEndian>()?;

        // 0x30 – content ID
        let mut content_id = [0u8; 48];
        inner.read_exact(&mut content_id)?;

        // 0x60 – qa_digest (used as key material in debug stream cipher)
        let mut qa_digest = [0u8; 16];
        inner.read_exact(&mut qa_digest)?;

        // 0x70 – klicensee (AES-CTR initial counter for retail)
        let mut klicensee = [0u8; 16];
        inner.read_exact(&mut klicensee)?;

        // 0x80 – header digest
        let mut header_digest = [0u8; 64];
        inner.read_exact(&mut header_digest)?;

        let header = PkgHeader {
            magic,
            release_type,
            platform,
            metadata_offset,
            metadata_count,
            metadata_size,
            item_count,
            total_size,
            data_offset,
            data_size,
            content_id,
            qa_digest,
            klicensee,
            header_digest,
        };

        // Basic sanity checks.
        let data_end = header
            .data_offset
            .checked_add(header.data_size)
            .ok_or(PkgError::DataOutOfBounds)?;
        if data_end > file_size {
            return Err(PkgError::DataOutOfBounds);
        }

        // ---- extended header (0xB0+) ----
        inner.seek(SeekFrom::Start(0xB0))?;
        let drm_type = inner.read_u32::<BigEndian>()?;
        let content_type = inner.read_u32::<BigEndian>()?;
        let package_type = inner.read_u16::<BigEndian>()?;
        let package_flag = inner.read_u16::<BigEndian>()?;
        let npdrm_revision = inner.read_u16::<BigEndian>()?;
        let package_version = inner.read_u16::<BigEndian>()?;

        // 0xC0 – 4 bytes padding, then Title-ID at 0xC4
        inner.seek(SeekFrom::Start(0xC4))?;
        let mut title_id = [0u8; 9];
        inner.read_exact(&mut title_id)?;
        let mut qa_digest = [0u8; 16];
        inner.read_exact(&mut qa_digest)?;

        // 0xE4
        inner.seek(SeekFrom::Start(0xE4))?;
        let system_version = inner.read_u32::<BigEndian>()?;
        let app_version = inner.read_u32::<BigEndian>()?;

        // 0xF0 – install directory
        inner.seek(SeekFrom::Start(0xF0))?;
        let mut install_directory = [0u8; 32];
        inner.read_exact(&mut install_directory)?;

        let ext_header = PkgExtendedHeader {
            drm_type,
            content_type,
            package_type,
            package_flag,
            npdrm_revision,
            package_version,
            title_id,
            qa_digest,
            system_version,
            app_version,
            install_directory,
        };

        // Select default AES key from platform.
        let aes_key = if platform == PkgPlatform::PSP as u16 {
            PSP_AES_KEY
        } else {
            PS3_AES_KEY
        };

        Ok(Self {
            inner,
            header,
            ext_header,
            file_size,
            aes_key,
        })
    }

    // -- accessors ----------------------------------------------------------

    /// Reference to the parsed main header.
    pub const fn header(&self) -> &PkgHeader {
        &self.header
    }

    /// Reference to the parsed extended header.
    pub const fn ext_header(&self) -> &PkgExtendedHeader {
        &self.ext_header
    }

    /// Whether the release-type field indicates a retail (encrypted with AES)
    /// package.  The high bit `0x8000` ("finalized") distinguishes retail
    /// from debug — values `0x8001` / `0x8002` are both retail.
    pub fn is_retail(&self) -> bool {
        self.header.release_type & 0x8000 != 0
    }

    /// Whether the release-type field indicates a debug package.
    pub fn is_debug(&self) -> bool {
        self.header.release_type & 0x8000 == 0
    }

    /// Number of file items declared in the header.
    pub const fn item_count(&self) -> u32 {
        self.header.item_count
    }

    // -- item table ---------------------------------------------------------

    /// Read a single raw [`PkgFileEntry`] by index from the item table.
    pub fn read_file_entry(&mut self, index: usize) -> Result<PkgFileEntry, PkgError> {
        if index >= self.header.item_count as usize {
            return Err(PkgError::EntryIndex(index));
        }

        let offset_in_data = index * PKG_FILE_ENTRY_SIZE;
        let buf = self.read_data_bytes(offset_in_data, PKG_FILE_ENTRY_SIZE)?;

        let mut c = io::Cursor::new(buf);
        let name_offset = c.read_u32::<BigEndian>()?;
        let name_size = c.read_u32::<BigEndian>()?;
        let data_offset = c.read_u64::<BigEndian>()?;
        let data_size = c.read_u64::<BigEndian>()?;
        let flags = c.read_u32::<BigEndian>()?;
        let padding = c.read_u32::<BigEndian>()?;

        Ok(PkgFileEntry {
            name_offset,
            name_size,
            data_offset,
            data_size,
            flags,
            padding,
        })
    }

    /// Read the name for a given [`PkgFileEntry`].
    ///
    /// If the entry has the PSP flag set, uses [`PSP_AES_KEY`] for retail
    /// decryption; otherwise uses the default platform key.
    pub fn read_entry_name(&mut self, entry: &PkgFileEntry) -> Result<String, PkgError> {
        let key = self.key_for_entry(entry);
        let buf = self.read_data_bytes_with_key(
            entry.name_offset as usize,
            entry.name_size as usize,
            &key,
        )?;

        // Strip trailing NULs and convert.
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8(buf[..end].to_vec()).map_err(|_| PkgError::InvalidEntryName(0))
    }

    /// Iterate over items lazily (more idiomatic than allocating a Vec).
    ///
    /// Example:
    /// ```ignore
    /// for item in pkg.items() {
    ///     let item = item?;
    ///     println!("{}", item.name);
    /// }
    /// ```
    pub fn items(&mut self) -> Items<'_, R> {
        Items::new(self)
    }

    /// Resolve all items into a `Vec<PkgItem>` (kept for compatibility).
    pub fn read_items(&mut self) -> Result<Vec<PkgItem>, PkgError> {
        let mut out = Vec::with_capacity(self.header.item_count as usize);
        for item_res in self.items() {
            out.push(item_res?);
        }
        Ok(out)
    }

    // -- file data ----------------------------------------------------------

    /// Read the data of an item by index.
    pub fn read_item_data(&mut self, index: usize) -> Result<Vec<u8>, PkgError> {
        let entry = self.read_file_entry(index)?;
        if entry.is_directory() {
            return Ok(Vec::new());
        }
        let key = self.key_for_entry(&entry);
        let buf = self.read_data_bytes_with_key(
            entry.data_offset as usize,
            entry.data_size as usize,
            &key,
        )?;
        Ok(buf)
    }

    /// Streaming reader over a single item's decrypted data.
    ///
    /// This returns a light-weight `PkgItemReader` that decrypts blocks on
    /// demand and implements `Read`. It borrows `&mut self` so the archive
    /// cannot be used while the reader is active.
    pub fn item_reader(&mut self, index: usize) -> Result<PkgItemReader<'_, R>, PkgError> {
        let entry = self.read_file_entry(index)?;
        let key = self.key_for_entry(&entry);
        Ok(PkgItemReader::new(self, entry, key))
    }

    /// Consume the reader and return the inner stream.
    pub fn into_inner(self) -> R {
        self.inner
    }

    // -- internal helpers ---------------------------------------------------

    /// Select the AES key appropriate for `entry`.
    ///
    /// PSP-flagged entries within a PS3 package use [`PSP_AES_KEY`];
    /// everything else uses the platform-default key.
    fn key_for_entry(&self, entry: &PkgFileEntry) -> [u8; 16] {
        if entry.is_psp() {
            PSP_AES_KEY
        } else {
            self.aes_key
        }
    }

    /// Read `len` bytes at `offset_in_data` inside the data area and decrypt
    /// them using the default platform key.
    fn read_data_bytes(&mut self, offset_in_data: usize, len: usize) -> Result<Vec<u8>, PkgError> {
        self.read_data_bytes_with_key(offset_in_data, len, &self.aes_key.clone())
    }

    /// Read `len` bytes at `offset_in_data` inside the data area and decrypt
    /// them using the supplied AES key (only relevant for retail release
    /// type).
    fn read_data_bytes_with_key(
        &mut self,
        offset_in_data: usize,
        len: usize,
        aes_key: &[u8; 16],
    ) -> Result<Vec<u8>, PkgError> {
        #[allow(
            unused_variables,
            reason = "defensive checks for overflow and out-of-bounds access"
        )]
        let end = offset_in_data
            .checked_add(len)
            .ok_or(PkgError::EntryOutOfBounds)?;

        let abs = self
            .header
            .data_offset
            .checked_add(offset_in_data as u64)
            .ok_or(PkgError::EntryOutOfBounds)?;
        if abs + len as u64 > self.file_size {
            return Err(PkgError::EntryOutOfBounds);
        }

        self.inner.seek(SeekFrom::Start(abs))?;
        let mut buf = vec![0u8; len];
        self.inner.read_exact(&mut buf)?;

        // Decrypt in-place.
        self.decrypt_in_place(&mut buf, offset_in_data as u64, aes_key);

        Ok(buf)
    }

    /// Dispatch decryption based on release type.
    ///
    /// The high bit `0x8000` of the release-type field determines the
    /// encryption scheme.  Lower bits encode the revision level and are
    /// ignored here.
    fn decrypt_in_place(&self, data: &mut [u8], offset_in_data: u64, aes_key: &[u8; 16]) {
        if data.is_empty() {
            return;
        }

        if self.header.release_type & 0x8000 != 0 {
            // Retail / finalized (AES-128-ECB-CTR).
            self.decrypt_retail(data, offset_in_data, aes_key);
        } else {
            // Debug (SHA-1 stream cipher).
            self.decrypt_debug(data, offset_in_data);
        }
    }

    /// Debug decryption: SHA-1-based stream cipher keyed on `qa_digest`.
    ///
    /// For each 16-byte block at index `b`:
    ///   input = `[qa0, qa0, qa1, qa1, 0, 0, 0, b]`  (8 × u64-BE = 64 bytes)
    ///   keystream = SHA-1(input)[0..16]
    ///   plaintext ^= keystream
    ///
    /// Handles reads that are not aligned to a 16-byte boundary.
    fn decrypt_debug(&self, data: &mut [u8], offset_in_data: u64) {
        let qa = &self.header.qa_digest;

        // Pre-build the 64-byte SHA-1 input template.
        let mut sha_input = [0u8; 64];
        sha_input[0..8].copy_from_slice(&qa[0..8]); // qa_digest[0]
        sha_input[8..16].copy_from_slice(&qa[0..8]); // qa_digest[0]  (dup)
        sha_input[16..24].copy_from_slice(&qa[8..16]); // qa_digest[1]
        sha_input[24..32].copy_from_slice(&qa[8..16]); // qa_digest[1] (dup)
        // bytes 32..56 = 0

        let mut pos = 0usize;
        while pos < data.len() {
            let abs_byte = offset_in_data + pos as u64;
            let block_idx = abs_byte / 16;
            let within = (abs_byte % 16) as usize;

            sha_input[56..64].copy_from_slice(&block_idx.to_be_bytes());
            let hash = Sha1::from(&sha_input).digest().bytes(); // [u8; 20]

            let n = std::cmp::min(16 - within, data.len() - pos);
            for k in 0..n {
                data[pos + k] ^= hash[within + k];
            }
            pos += n;
        }
    }

    /// Retail decryption: AES-128-ECB-CTR with `klicensee` as initial
    /// counter.
    ///
    /// counter = klicensee + block_index
    /// keystream = AES_ECB_ENCRYPT(key, counter)
    /// plaintext ^= keystream
    ///
    /// Handles reads that are not aligned to a 16-byte boundary.
    fn decrypt_retail(&self, data: &mut [u8], offset_in_data: u64, aes_key: &[u8; 16]) {
        let cipher = Aes128::new(aes_key.into());
        let klicensee = u128::from_be_bytes(self.header.klicensee);

        let mut pos = 0usize;
        while pos < data.len() {
            let abs_byte = offset_in_data + pos as u64;
            let block_idx = abs_byte / 16;
            let within = (abs_byte % 16) as usize;

            let ctr = klicensee.wrapping_add(block_idx as u128);
            let mut block = Block::clone_from_slice(&ctr.to_be_bytes());
            cipher.encrypt_block(&mut block);

            let n = std::cmp::min(16 - within, data.len() - pos);
            for k in 0..n {
                data[pos + k] ^= block[within + k];
            }
            pos += n;
        }
    }
}

// -----------------------------------------------------------------------
// Iterators / streaming readers (more idiomatic API)
// -----------------------------------------------------------------------

/// Iterator over `PkgItem`s that borrows the archive.
pub struct Items<'a, R: Read + Seek> {
    archive: &'a mut PkgArchive<R>,
    idx: usize,
    total: usize,
}

impl<'a, R: Read + Seek> Items<'a, R> {
    fn new(archive: &'a mut PkgArchive<R>) -> Self {
        let total = archive.header.item_count as usize;
        Self {
            archive,
            idx: 0,
            total,
        }
    }
}

impl<'a, R: Read + Seek> Iterator for Items<'a, R> {
    type Item = Result<PkgItem, PkgError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.total {
            return None;
        }

        let i = self.idx;
        self.idx += 1;

        match self.archive.read_file_entry(i) {
            Ok(entry) => {
                let name = match self.archive.read_entry_name(&entry) {
                    Ok(s) => s,
                    Err(_) => format!("__unnamed_{i:04}"),
                };
                Some(Ok(PkgItem {
                    index: i as u32,
                    name,
                    entry,
                }))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Streaming reader that decrypts an item's data on demand.
///
/// Borrows `&mut PkgArchive` so no other archive operations may run while
/// the reader is alive.
pub struct PkgItemReader<'a, R: Read + Seek> {
    archive: &'a mut PkgArchive<R>,
    entry: PkgFileEntry,
    pos: u64, // bytes read from start of entry
    end: u64, // entry.data_size
    key: [u8; 16],
    buf: [u8; 16],  // cached decrypted block
    buf_block: u64, // block index currently cached in `buf`
    buf_valid: bool,
}

impl<'a, R: Read + Seek> PkgItemReader<'a, R> {
    fn new(archive: &'a mut PkgArchive<R>, entry: PkgFileEntry, key: [u8; 16]) -> Self {
        Self {
            archive,
            entry,
            pos: 0,
            end: entry.data_size,
            key,
            buf: [0u8; 16],
            buf_block: 0,
            buf_valid: false,
        }
    }
}

impl<'a, R: Read + Seek> Read for PkgItemReader<'a, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.end {
            return Ok(0);
        }

        let mut written = 0usize;
        while written < out.len() && self.pos < self.end {
            let abs_data_offset = self.entry.data_offset + self.pos;
            let block_idx = abs_data_offset / 16; // index relative to data area
            let start_in_block = (abs_data_offset % 16) as usize;

            if !self.buf_valid || self.buf_block != block_idx {
                // Read and decrypt the whole 16-byte block from disk.
                let abs_file = self.archive.header.data_offset + block_idx * 16;
                self.archive.inner.seek(SeekFrom::Start(abs_file))?;
                self.archive.inner.read_exact(&mut self.buf)?;
                // Decrypt the block in-place using archive helper.
                self.archive
                    .decrypt_in_place(&mut self.buf, (block_idx * 16) as u64, &self.key);
                self.buf_block = block_idx;
                self.buf_valid = true;
            }

            let remaining_in_entry = (self.end - self.pos) as usize;
            let avail = std::cmp::min(16 - start_in_block, remaining_in_entry);
            let want = std::cmp::min(avail, out.len() - written);

            out[written..written + want]
                .copy_from_slice(&self.buf[start_in_block..start_in_block + want]);

            self.pos += want as u64;
            written += want;
        }

        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    /// Apply the debug stream cipher to `data` starting at `offset_in_data`.
    /// Since XOR is its own inverse this works for both encrypt and decrypt.
    fn debug_cipher(data: &mut [u8], offset_in_data: u64, qa_digest: &[u8; 16]) {
        let mut sha_input = [0u8; 64];
        sha_input[0..8].copy_from_slice(&qa_digest[0..8]);
        sha_input[8..16].copy_from_slice(&qa_digest[0..8]);
        sha_input[16..24].copy_from_slice(&qa_digest[8..16]);
        sha_input[24..32].copy_from_slice(&qa_digest[8..16]);

        let blocks = (data.len() + 15) / 16;
        for i in 0..blocks {
            let block_idx = offset_in_data / 16 + i as u64;
            sha_input[56..64].copy_from_slice(&block_idx.to_be_bytes());
            let hash = Sha1::from(&sha_input).digest().bytes();
            let start = i * 16;
            let end = std::cmp::min(start + 16, data.len());
            for j in start..end {
                data[j] ^= hash[j - start];
            }
        }
    }

    /// Helper: build a minimal **debug** PKG in memory.
    ///
    /// Contains two items:
    ///   0 – directory "USRDIR"
    ///   1 – file      "USRDIR/hello.txt"  with body `b"Hello!"`
    ///
    /// The data area is encrypted with the debug SHA-1 stream cipher.
    pub(crate) fn build_debug_pkg() -> Vec<u8> {
        use byteorder::WriteBytesExt;

        let name_a = b"USRDIR\0";
        let name_b = b"USRDIR/hello.txt\0";
        let file_data = b"Hello!";

        let item_count: u32 = 2;
        let entry_table_size = (item_count as usize) * PKG_FILE_ENTRY_SIZE;

        let name_a_off = entry_table_size as u32;
        let name_b_off = name_a_off + name_a.len() as u32;
        let file_data_off = name_b_off + name_b.len() as u32;
        let data_size = entry_table_size + name_a.len() + name_b.len() + file_data.len();

        let data_offset: u64 = 0x0110;
        let total_size = data_offset + data_size as u64;

        let qa_digest: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];

        let mut buf: Vec<u8> = vec![0u8; total_size as usize];
        {
            let mut c = io::Cursor::new(&mut buf[..]);

            // 0x00 – magic
            c.write_u32::<BigEndian>(PKG_MAGIC).unwrap();
            // 0x04 – release_type (debug)
            c.write_u16::<BigEndian>(PkgReleaseType::Debug as u16)
                .unwrap();
            // 0x06 – platform (PS3)
            c.write_u16::<BigEndian>(PkgPlatform::PS3 as u16).unwrap();
            // 0x08 – metadata_offset, count, size
            c.write_u32::<BigEndian>(0).unwrap();
            c.write_u32::<BigEndian>(0).unwrap();
            c.write_u32::<BigEndian>(0).unwrap();
            // 0x14 – item_count
            c.write_u32::<BigEndian>(item_count).unwrap();
            // 0x18 – total_size
            c.write_u64::<BigEndian>(total_size).unwrap();
            // 0x20 – data_offset
            c.write_u64::<BigEndian>(data_offset).unwrap();
            // 0x28 – data_size
            c.write_u64::<BigEndian>(data_size as u64).unwrap();
            // 0x30 – content_id (48 bytes)
            let cid = b"UP0001-TEST00001_00-0000000000000000";
            c.write_all(cid).unwrap();
            c.write_all(&vec![0u8; 48 - cid.len()]).unwrap();
            // 0x60 – qa_digest (debug cipher key material)
            c.write_all(&qa_digest).unwrap();
            // 0x70 – klicensee (16)
            c.write_all(&[0u8; 16]).unwrap();
            // 0x80 – header_digest (64)
            c.write_all(&[0u8; 64]).unwrap();

            // Extended header (0xB0+)
            c.set_position(0xB0);
            c.write_u32::<BigEndian>(0).unwrap(); // drm
            c.write_u32::<BigEndian>(0x04).unwrap(); // content type
            c.write_u16::<BigEndian>(0).unwrap(); // pkg type
            c.write_u16::<BigEndian>(0).unwrap(); // pkg flag
            c.write_u16::<BigEndian>(0).unwrap(); // npdrm rev
            c.write_u16::<BigEndian>(0).unwrap(); // pkg ver

            // 0xC4 – title id + qa_digest
            c.set_position(0xC4);
            c.write_all(b"TEST00001").unwrap();
            c.write_all(&qa_digest).unwrap();
            // 0xE4
            c.set_position(0xE4);
            c.write_u32::<BigEndian>(0).unwrap();
            c.write_u32::<BigEndian>(0).unwrap();
            // 0xF0 – install directory
            c.set_position(0xF0);
            c.write_all(b"TEST00001\0").unwrap();
            c.write_all(&vec![0u8; 32 - 10]).unwrap();

            // Build plaintext data area, then encrypt with debug cipher.
            let mut plaintext = vec![0u8; data_size];
            {
                let mut dc = io::Cursor::new(&mut plaintext[..]);

                // Entry 0: directory "USRDIR"
                dc.write_u32::<BigEndian>(name_a_off).unwrap();
                dc.write_u32::<BigEndian>(name_a.len() as u32).unwrap();
                dc.write_u64::<BigEndian>(0).unwrap();
                dc.write_u64::<BigEndian>(0).unwrap();
                dc.write_u32::<BigEndian>(0x04).unwrap();
                dc.write_u32::<BigEndian>(0).unwrap();

                // Entry 1: file "USRDIR/hello.txt"
                dc.write_u32::<BigEndian>(name_b_off).unwrap();
                dc.write_u32::<BigEndian>(name_b.len() as u32).unwrap();
                dc.write_u64::<BigEndian>(file_data_off as u64).unwrap();
                dc.write_u64::<BigEndian>(file_data.len() as u64).unwrap();
                dc.write_u32::<BigEndian>(0x01).unwrap();
                dc.write_u32::<BigEndian>(0).unwrap();

                // Names
                dc.set_position(name_a_off as u64);
                dc.write_all(name_a).unwrap();
                dc.write_all(name_b).unwrap();

                // File data
                dc.set_position(file_data_off as u64);
                dc.write_all(file_data).unwrap();
            }

            debug_cipher(&mut plaintext, 0, &qa_digest);

            c.set_position(data_offset);
            c.write_all(&plaintext).unwrap();
        }

        buf
    }

    #[test]
    fn opens_and_reads_debug_pkg() {
        let buf = build_debug_pkg();
        let cur = io::Cursor::new(buf);
        let pkg = PkgArchive::open(cur).unwrap();

        assert!(pkg.header().is_valid_magic());
        assert!(!pkg.is_retail());
        assert!(pkg.is_debug());
        assert_eq!(pkg.item_count(), 2);
        assert_eq!(
            pkg.header().content_id_str(),
            "UP0001-TEST00001_00-0000000000000000"
        );
        assert_eq!(pkg.ext_header().title_id_str(), "TEST00001");
    }

    #[test]
    fn reads_items_and_data() {
        let buf = build_debug_pkg();
        let cur = io::Cursor::new(buf);
        let mut pkg = PkgArchive::open(cur).unwrap();

        let items = pkg.read_items().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "USRDIR");
        assert!(items[0].entry.is_directory());
        assert_eq!(items[1].name, "USRDIR/hello.txt");
        assert!(!items[1].entry.is_directory());

        let data = pkg.read_item_data(1).unwrap();
        assert_eq!(data, b"Hello!");
    }

    #[test]
    fn item_reader_streams_data() {
        let buf = build_debug_pkg();
        let cur = io::Cursor::new(buf);
        let mut pkg = PkgArchive::open(cur).unwrap();

        let mut r = pkg.item_reader(1).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"Hello!");
    }

    #[test]
    fn items_iterator_works() {
        let buf = build_debug_pkg();
        let cur = io::Cursor::new(buf);
        let mut pkg = PkgArchive::open(cur).unwrap();

        let mut it = pkg.items();
        let first = it.next().unwrap().unwrap();
        assert_eq!(first.name, "USRDIR");
        let second = it.next().unwrap().unwrap();
        assert_eq!(second.name, "USRDIR/hello.txt");
        assert!(it.next().is_none());
    }

    #[test]
    fn streaming_reader_partial_reads() {
        let buf = build_debug_pkg();
        let cur = io::Cursor::new(buf);
        let mut pkg = PkgArchive::open(cur).unwrap();

        let mut r = pkg.item_reader(1).unwrap(); // "Hello!"
        let mut small = [0u8; 3];
        assert_eq!(r.read(&mut small).unwrap(), 3);
        assert_eq!(&small, b"Hel");

        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"lo!");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = build_debug_pkg();
        buf[0] = 0x00;
        let cur = io::Cursor::new(buf);
        assert!(matches!(PkgArchive::open(cur), Err(PkgError::InvalidMagic)));
    }
}
