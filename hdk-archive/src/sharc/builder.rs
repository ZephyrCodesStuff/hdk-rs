use std::io::{Seek, Write};

use binrw::BinWrite;
use ctr::cipher::{KeyIvInit, StreamCipher};
use flate2::write::ZlibEncoder;
use hdk_comp::zlib::writer::SegmentedZlibWriter;
use hdk_secure::{hash::AfsHash, modes::XteaPS3};
use rand::Rng;

use super::structs::{SharcArchive, SharcArchiveData, SharcArchiveMeta, SharcEntry};
use crate::structs::CompressionType;

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
}

struct SharcBuilderEntry {
    name_hash: AfsHash,
    data: Vec<u8>,
    compression: CompressionType,
    iv: [u8; 8],
}

impl SharcBuilder {
    /// Create a new builder with the given archive key.
    pub fn new(archive_key: [u8; 32], files_key: [u8; 16]) -> Self {
        SharcBuilder {
            archive_key,
            files_key,
            entries: Vec::new(),
            priority: 0,
            timestamp: 0,
        }
    }

    /// Set archive priority (used when multiple archives have same filename).
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Set archive timestamp.
    pub fn with_timestamp(mut self, timestamp: i32) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Add an entry to the archive.
    pub fn add_entry(
        &mut self,
        name_hash: AfsHash,
        data: Vec<u8>,
        compression: CompressionType,
        iv: [u8; 8],
    ) {
        self.entries.push(SharcBuilderEntry {
            name_hash,
            data,
            compression,
            iv,
        });
    }

    /// Compress data according to the compression type.
    fn compress_entry(
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
                // Compress first
                let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(data)?;
                let compressed = encoder.finish()?;

                // Then encrypt with XTEA-CTR
                let mut encrypted = compressed.clone();
                let mut cipher = XteaPS3::new(key.into(), iv.into());
                cipher.apply_keystream(&mut encrypted);
                Ok(encrypted)
            }
        }
    }

    /// Build the archive and write it to the given writer.
    pub fn build<W: Write + Seek>(&self, writer: &mut W) -> std::io::Result<()> {
        if self.entries.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot build empty archive",
            ));
        }

        // Generate random IV for archive metadata
        let mut archive_iv = [0u8; 16];
        let mut rng = rand::rng();
        rng.fill(&mut archive_iv);

        // Calculate offsets for all entries
        let mut entry_offsets = Vec::new();
        let mut current_offset = 0u32;

        for entry in &self.entries {
            let compressed =
                Self::compress_entry(&entry.data, entry.compression, &self.files_key, &entry.iv)?;

            entry_offsets.push((current_offset, compressed.len() as u32));
            current_offset = current_offset.wrapping_add(compressed.len() as u32);
        }

        // Build archive structure
        let archive = SharcArchive {
            archive_info: SharcArchiveMeta {
                version: 512,
                flags: 0,
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
                    uncompressed_size: entry.data.len() as u32,
                    compressed_size: *compressed_size,
                    iv: entry.iv,
                })
                .collect(),
        };

        // Write archive (binrw handles encryption via map_stream)
        archive
            .write_le_args(writer, (self.archive_key,))
            .map_err(|e| std::io::Error::other(format!("Failed to write archive: {e}")))?;

        // Write compressed file data
        for entry in &self.entries {
            let compressed =
                Self::compress_entry(&entry.data, entry.compression, &self.files_key, &entry.iv)?;
            writer.write_all(&compressed)?;
        }

        Ok(())
    }
}
