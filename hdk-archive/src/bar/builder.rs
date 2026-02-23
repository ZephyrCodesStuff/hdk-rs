use std::io::{Seek, Write};

use binrw::{BinWrite, Endian};
use ctr::cipher::KeyIvInit;
use flate2::write::ZlibEncoder;
use hdk_comp::zlib::writer::SegmentedZlibWriter;
use hdk_secure::{hash::AfsHash, modes::BlowfishPS3, writer::CryptoWriter};

use super::structs::{BarArchive, BarArchiveData, BarArchiveMeta, BarEntry};
use crate::structs::{ArchiveVersion, CompressionType};

/// Builder for creating BAR archives.
///
/// Allows adding entries with various compression types, then finalizes
/// the archive to binary format.
pub struct BarBuilder {
    archive_key: [u8; 32],
    signature_key: [u8; 32],
    entries: Vec<BarBuilderEntry>,
    priority: i32,
    timestamp: i32,
    flags: u16,
}

struct BarBuilderEntry {
    name_hash: AfsHash,
    data: Vec<u8>,
    compression: CompressionType,
}

impl BarBuilderEntry {
    pub fn sha1(&self) -> [u8; 20] {
        let mut hasher = sha1_smol::Sha1::new();
        hasher.update(&self.data);
        hasher.digest().bytes()
    }
}

impl BarBuilder {
    /// Create a new builder with the given keys.
    pub fn new(archive_key: [u8; 32], signature_key: [u8; 32]) -> Self {
        BarBuilder {
            archive_key,
            signature_key,
            entries: Vec::new(),
            priority: 0,
            timestamp: 0,
            flags: 0,
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

    /// Set archive flags.
    pub fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Add an entry to the archive.
    pub fn add_entry(&mut self, name_hash: AfsHash, data: Vec<u8>, compression: CompressionType) {
        self.entries.push(BarBuilderEntry {
            name_hash,
            data,
            compression,
        });
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

        // Sort entries decreasing by name hash to match expected order
        self.entries
            .sort_by_key(|e| std::cmp::Reverse(e.name_hash.0));

        let file_count = self.entries.len() as u32;

        // Pass 1: Handle compression and initial size calculation
        let mut entry_compressed_data = Vec::with_capacity(self.entries.len());
        let mut entry_offsets = Vec::with_capacity(self.entries.len());
        let mut current_offset = 0u32;

        for entry in &self.entries {
            let data = match entry.compression {
                CompressionType::None => entry.data.clone(),
                CompressionType::ZLib => {
                    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                    encoder.write_all(&entry.data)?;
                    encoder.finish()?
                }
                CompressionType::EdgeZLib | CompressionType::Encrypted => {
                    let mut encoder = SegmentedZlibWriter::new(Vec::new());
                    encoder.write_all(&entry.data)?;
                    encoder.finish()?
                }
            };

            let entry_size = if entry.compression == CompressionType::Encrypted {
                // If encrypted, the TOC entry size includes the head and fourcc (24 + 4 = 28 bytes)
                data.len() as u32 + 28
            } else {
                data.len() as u32
            };

            entry_offsets.push((current_offset, entry_size));
            entry_compressed_data.push(data);
            current_offset = (current_offset + entry_size + 3) & !3; // Align to 4 bytes
        }

        // Pass 2: Handle Encryption for Encrypted entries
        let mut final_entry_data = Vec::with_capacity(self.entries.len());
        for (i, entry) in self.entries.iter().enumerate() {
            let compressed = &entry_compressed_data[i];
            let (offset, total_size) = entry_offsets[i];

            if entry.compression == CompressionType::Encrypted {
                let checksum = entry.sha1();

                // Forge IV using relative offset (forge_iv adds header base internally)
                let iv = super::forge_iv(
                    u64::from(file_count),
                    u64::from(entry.data.len() as u32),
                    u64::from(total_size),
                    u64::from(offset),
                    self.timestamp,
                );

                // Build head: 4B fourcc (zeros) + 20B checksum
                let mut head = Vec::with_capacity(24);
                head.extend_from_slice(&[0u8; 4]);
                head.extend_from_slice(&checksum);

                // Encrypt head with signature_key
                let mut head_enc = Vec::new();
                let mut head_writer = CryptoWriter::new(
                    &mut head_enc,
                    BlowfishPS3::new(&self.signature_key.into(), &iv.into()),
                );
                head_writer.write_all(&head)?;
                drop(head_writer);

                // Encrypt body with default_key using IV + 3
                let mut iv_as_u64 = u64::from_be_bytes(iv);
                iv_as_u64 = iv_as_u64.wrapping_add(3);
                let iv_body = iv_as_u64.to_be_bytes();

                let mut body_enc = Vec::new();
                let mut body_writer = CryptoWriter::new(
                    &mut body_enc,
                    BlowfishPS3::new(&self.signature_key.into(), &iv_body.into()),
                );
                body_writer.write_all(compressed)?;
                drop(body_writer);

                // Compose final data: head_enc (24B), body_fourcc (4B zeros), body_enc
                let mut final_data = Vec::with_capacity(28 + body_enc.len());
                final_data.extend_from_slice(&head_enc);
                final_data.extend_from_slice(&[0u8; 4]); // body_fourcc
                final_data.extend_from_slice(&body_enc);
                final_entry_data.push(final_data);
            } else {
                final_entry_data.push(compressed.clone());
            }
        }

        // Build archive structure for TOC
        let archive = BarArchive {
            archive_info: BarArchiveMeta {
                version: ArchiveVersion::BAR.into(),
                flags: self.flags,
            },
            archive_data: BarArchiveData {
                priority: self.priority,
                timestamp: self.timestamp,
                file_count,
            },
            entries: self
                .entries
                .iter()
                .zip(entry_offsets.iter())
                .map(|(entry, (offset, compressed_size))| BarEntry {
                    name_hash: entry.name_hash,
                    location: (*offset, entry.compression),
                    uncompressed_size: entry.data.len() as u32,
                    compressed_size: *compressed_size,
                    iv: [0u8; 8], // Automatically calculated in structs.rs calc
                })
                .collect(),
        };

        // Write metadata and TOC
        match endian {
            Endian::Little => archive.write_le_args(writer, (self.archive_key, self.signature_key)),
            Endian::Big => archive.write_be_args(writer, (self.archive_key, self.signature_key)),
        }
        .map_err(|e| std::io::Error::other(format!("Failed to write archive header: {e}")))?;

        // Write file data blobs
        for data in final_entry_data {
            writer.write_all(&data)?;

            // Alignment padding
            let padding_needed = (4 - (data.len() % 4)) % 4;
            if padding_needed > 0 {
                writer.write_all(&[0u8, 0u8, 0u8][..padding_needed])?;
            }
        }

        Ok(())
    }
}
