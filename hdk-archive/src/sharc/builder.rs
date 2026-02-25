use std::io::{Seek, Write};

use binrw::{BinWrite, Endian};
use ctr::cipher::{KeyIvInit, StreamCipher};
use flate2::write::ZlibEncoder;
use hdk_comp::zlib::writer::SegmentedZlibWriter;
use hdk_secure::{hash::AfsHash, modes::XteaPS3};
use rand::Rng;

use super::structs::{SharcArchive, SharcArchiveData, SharcArchiveMeta, SharcEntry};
use crate::structs::{ArchiveFlags, CompressionType};

// Builder for creating SHARC archives.
///
/// Allows adding entries with various compression types, then finalizes
/// the archive to binary format.
pub struct SharcBuilder {
    archive_key: [u8; 32],
    files_key: [u8; 16],
    entries: Vec<SharcBuilderEntry>,
    priority: i32,
    timestamp: i32,
    flags: ArchiveFlags,
}

struct SharcBuilderEntry {
    name_hash: AfsHash,
    data: Vec<u8>,
    uncompressed_size: u32,

    /// Compression type to use for this entry (affects how data is stored in the archive).
    compression: CompressionType,

    /// Whether the data is already compressed (added via `add_compressed_entry`).
    pre_compressed: bool,

    iv: [u8; 8],
}

impl SharcBuilder {
    /// Create a new builder with the given archive key.
    pub fn new(archive_key: [u8; 32], files_key: [u8; 16]) -> Self {
        Self {
            archive_key,
            files_key,
            entries: Vec::new(),
            priority: 0,
            timestamp: 0,
            flags: ArchiveFlags::default(),
        }
    }

    /// Set archive priority (used when multiple archives have same filename).
    pub const fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Set archive timestamp.
    pub const fn with_timestamp(mut self, timestamp: i32) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set archive flags.
    pub const fn with_flags(mut self, flags: ArchiveFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Add an entry to the archive with uncompressed data.
    ///
    /// The data will be compressed during `build()` according to the specified compression type.
    /// For parallel compression outside the library, use `compress_data()` then `add_compressed_entry()`.
    pub fn add_entry(
        &mut self,
        name_hash: AfsHash,
        data: Vec<u8>,
        compression: CompressionType,
        iv: [u8; 8],
    ) {
        let uncompressed_size = data.len() as u32;
        self.entries.push(SharcBuilderEntry {
            name_hash,
            data,
            uncompressed_size,
            compression,
            pre_compressed: false,
            iv,
        });
    }

    /// Add an entry with data that has already been compressed externally.
    ///
    /// Use this with `compress_data()` to handle compression in parallel (e.g., with rayon).
    pub fn add_compressed_entry(
        &mut self,
        name_hash: AfsHash,
        compressed_data: Vec<u8>,
        uncompressed_size: u32,
        compression: CompressionType,
        iv: [u8; 8],
    ) {
        self.entries.push(SharcBuilderEntry {
            name_hash,
            data: compressed_data,
            uncompressed_size,
            compression,
            pre_compressed: true,
            iv,
        });
    }

    /// Compress data using this builder's cryptographic keys.
    ///
    /// This is a pure function that can be called in parallel (e.g., with rayon) outside the library.
    /// The result can be added with `add_compressed_entry()`.
    pub fn compress_data(
        &self,
        data: &[u8],
        compression: CompressionType,
        iv: &[u8; 8],
    ) -> std::io::Result<Vec<u8>> {
        Self::compress_entry(data, compression, &self.files_key, iv)
    }

    /// Compress data according to the compression type.
    pub fn compress_entry(
        data: &[u8],
        compression: CompressionType,
        key: &[u8; 16],
        iv: &[u8; 8],
    ) -> std::io::Result<Vec<u8>> {
        match compression {
            CompressionType::None => Ok(data.to_vec()),

            CompressionType::ZLib => {
                let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(data)?;
                encoder.finish()
            }

            CompressionType::EdgeZLib => {
                let mut encoder = SegmentedZlibWriter::new(Vec::new());
                encoder.write_all(data)?;
                encoder.finish()
            }

            CompressionType::Encrypted => {
                // Compress first with SegmentedZlib (matching the reader's decompression)
                let mut encoder = SegmentedZlibWriter::new(Vec::new());
                encoder.write_all(data)?;
                let mut compressed = encoder.finish()?;

                // Then encrypt with XTEA-CTR
                let mut cipher = XteaPS3::new(key.into(), iv.into());
                cipher.apply_keystream(&mut compressed);

                Ok(compressed)
            }
        }
    }

    /// Build the archive and write it to the given writer.
    pub fn build<W: Write + Seek>(
        &mut self,
        writer: &mut W,
        endian: Endian,
    ) -> std::io::Result<()> {
        if self.entries.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot build empty archive",
            ));
        }

        // Sort entries decreasing by name hash to match expected order in SHARC files
        self.entries
            .sort_by_key(|e| std::cmp::Reverse(e.name_hash.0));

        // Generate random IV for archive metadata
        let mut archive_iv = [0u8; 16];
        let mut rng = rand::rng();
        rng.fill(&mut archive_iv);

        // Calculate offsets for all entries (aligned to 4 bytes)
        let mut entry_offsets = Vec::new();
        let mut current_offset = 0u32;
        let compressed: Vec<Vec<u8>> = self
            .entries
            .iter()
            .map(|entry| {
                let data = if entry.pre_compressed {
                    // Data is already compressed, use as-is
                    entry.data.clone()
                } else {
                    // Compress according to the specified compression type
                    Self::compress_entry(&entry.data, entry.compression, &self.files_key, &entry.iv)
                        .expect("Failed to compress entry")
                };

                entry_offsets.push((current_offset, data.len() as u32));
                current_offset = (current_offset + data.len() as u32 + 3) & !3; // Align to next 4-byte boundary

                data
            })
            .collect();

        // Build archive structure
        let archive = SharcArchive {
            archive_info: SharcArchiveMeta {
                version: 512,
                flags: self.flags.0.bits(),
            },
            iv: archive_iv,
            archive_data: SharcArchiveData {
                priority: self.priority,
                timestamp: self.timestamp,
                file_count: self.entries.len() as u32,
                key: self.files_key,
            },
            entries: self
                .entries
                .iter()
                .zip(entry_offsets.iter())
                .map(|(entry, (offset, compressed_size))| SharcEntry {
                    name_hash: entry.name_hash,
                    location: (*offset, entry.compression),
                    uncompressed_size: entry.uncompressed_size,
                    compressed_size: *compressed_size,
                    iv: entry.iv,
                })
                .collect(),
        };

        // Write archive metadata and entry table
        match endian {
            Endian::Little => archive.write_le_args(writer, (self.archive_key,)),
            Endian::Big => archive.write_be_args(writer, (self.archive_key,)),
        }
        .map_err(|e| std::io::Error::other(format!("Failed to write archive: {e}")))?;

        // Write compressed file data with 4-byte alignment padding
        for entry in compressed {
            writer.write_all(&entry)?;

            // Write padding to align to next 4-byte boundary
            let padding_needed = (4 - (entry.len() % 4)) % 4;
            if padding_needed > 0 {
                writer.write_all(&vec![0u8; padding_needed])?;
            }
        }

        Ok(())
    }
}
