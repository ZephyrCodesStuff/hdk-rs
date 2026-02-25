use std::io::{Seek, Write};

use binrw::{BinWrite, Endian};
use ctr::cipher::{KeyIvInit, StreamCipher};
use flate2::write::ZlibEncoder;
use hdk_comp::zlib::writer::SegmentedZlibWriter;
use hdk_secure::{hash::AfsHash, modes::BlowfishPS3};
use smallvec::SmallVec;

use super::structs::{BarArchive, BarArchiveData, BarArchiveMeta, BarEntry};
use crate::structs::{ArchiveFlags, ArchiveVersion, CompressionType};

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
    flags: ArchiveFlags,
}

struct BarBuilderEntry {
    name_hash: AfsHash,
    data: SmallVec<[u8; 16_384]>, // Use SmallVec to avoid heap allocation for small files
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
        Self {
            archive_key,
            signature_key,
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

    /// Add an entry to the archive.
    pub fn add_entry<D>(&mut self, name_hash: AfsHash, data: D, compression: CompressionType)
    where
        D: Into<SmallVec<[u8; 16_384]>>,
    {
        self.entries.push(BarBuilderEntry {
            name_hash,
            data: data.into(),
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

        // Pre-calculate entry metadata
        let file_count = self.entries.len();
        let mut final_entry_data = Vec::with_capacity(file_count);
        let mut entry_offsets = Vec::with_capacity(file_count);
        let mut current_offset = 0u32;

        // Use drain() to take ownership of entries without cloning
        for entry in self.entries.drain(..) {
            let checksum = entry.sha1();
            let uncompressed_size = entry.data.len() as u32;

            // Compression
            let compressed = match entry.compression {
                CompressionType::None => entry.data, // SmallVec::from_vec
                CompressionType::ZLib => {
                    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                    encoder.write_all(&entry.data)?;
                    encoder.finish().map(SmallVec::from_vec)?
                }
                CompressionType::EdgeZLib | CompressionType::Encrypted => {
                    let mut encoder = SegmentedZlibWriter::new(Vec::new());
                    encoder.write_all(&entry.data)?;
                    encoder.finish().map(SmallVec::from_vec)?
                }
            };

            // Encryption
            let final_data = if entry.compression == CompressionType::Encrypted {
                let compressed_len = compressed.len() as u32;
                let total_size = compressed_len + 28;

                // Forge IV
                let iv = super::forge_iv(
                    u64::from(file_count as u32),
                    u64::from(uncompressed_size),
                    u64::from(total_size),
                    u64::from(current_offset),
                    self.timestamp,
                );

                // Build and Encrypt Head
                let mut head = [0u8; 24]; // Use a fixed array on the stack!
                head[4..24].copy_from_slice(&checksum);

                let mut head_enc = [0u8; 24];
                let mut head_cipher = BlowfishPS3::new(&self.signature_key.into(), &iv.into());
                // apply_keystream is in-place, much faster than CryptoWriter for fixed sizes
                head_enc.copy_from_slice(&head);
                head_cipher.apply_keystream(&mut head_enc);

                // Prepare Body IV
                let iv_as_u64 = u64::from_be_bytes(iv);
                let iv_body = iv_as_u64.wrapping_add(3).to_be_bytes();

                // Encrypt Body
                let mut body_enc = compressed; // Take ownership of the compressed SmallVec
                let mut body_cipher = BlowfishPS3::new(&self.archive_key.into(), &iv_body.into());
                body_cipher.apply_keystream(&mut body_enc);

                // Compose Final Data (Stack + Heap hybrid)
                let mut composed = SmallVec::with_capacity(28 + body_enc.len());
                composed.extend_from_slice(&head_enc);
                composed.extend_from_slice(&[0u8; 4]);
                composed.extend_from_slice(&body_enc);
                composed
            } else {
                compressed // No encryption, just pass the SmallVec through
            };

            let entry_size = final_data.len() as u32;
            entry_offsets.push((current_offset, entry_size));
            final_entry_data.push(final_data);

            current_offset = (current_offset + entry_size + 3) & !3;
        }

        // Build archive structure for TOC
        let archive = BarArchive {
            archive_info: BarArchiveMeta {
                version: ArchiveVersion::BAR.into(),
                flags: self.flags.0.bits(),
            },
            archive_data: BarArchiveData {
                priority: self.priority,
                timestamp: self.timestamp,
                file_count: file_count as u32,
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
