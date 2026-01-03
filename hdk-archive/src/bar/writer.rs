use byteorder::{LittleEndian, WriteBytesExt};
use enumflags2::BitFlags;
use flate2::{Compression, write::ZlibEncoder};
use std::io::{self, Cursor, Read, Write};

use ctr::Ctr64BE;
use ctr::cipher::KeyIvInit;
use hdk_comp::zlib::writer::SegmentedZlibWriter;
use hdk_secure::{blowfish::Blowfish, hash::AfsHash, writer::CryptoWriter};

use crate::structs::{ARCHIVE_MAGIC, ArchiveFlags, ArchiveVersion, CompressionType};

pub struct BarWriter<W: Write> {
    /// The underlying writer.
    ///
    /// This is where the archive data is written to.
    inner: W,

    /// The archive flags to write in the header.
    ///
    /// Default is no flags.
    flags: BitFlags<ArchiveFlags>,

    /// The timestamp of the archive.
    ///
    /// This is often random bytes in original Home archives,
    /// but `hdk-rs` uses the device's local time by default.
    timestamp: i32,

    /// The list of entries to write.
    ///
    /// Each entry holds its data in-memory until `finish()` is called.
    entries: Vec<BarEntryToWrite>,

    /// The default Blowfish key used for encrypting file bodies.
    ///
    /// This is used in CTR mode with an IV derived from the entry metadata.
    default_key: [u8; 32],

    /// The signature Blowfish key used for encrypting file headers.
    ///
    /// This is used in CTR mode with an IV derived from the entry metadata.
    signature_key: [u8; 32],
}

struct BarEntryToWrite {
    name_hash: AfsHash,
    compression: CompressionType,
    uncompressed_size: u32,
    compressed_size: u32,
    data: Vec<u8>,
    offset: u32,

    // For encrypted entries we need to store the checksum of the uncompressed body
    // so that we can forge the encrypted head when writing the archive (after
    // file offsets are known).
    sha1: Option<[u8; 20]>,
}

impl Default for BarWriter<std::io::Cursor<Vec<u8>>> {
    fn default() -> Self {
        Self::new(std::io::Cursor::new(Vec::new()), [0u8; 32], [0u8; 32]).unwrap()
    }
}

// TODO: make endianness configurable
impl<W: Write> BarWriter<W> {
    /// Create a new BAR archive writer.
    ///
    /// # Arguments
    ///
    /// * `inner` - The underlying writer to write the archive to.
    /// * `default_key` - The Blowfish key used for encrypting file bodies.
    /// * `signature_key` - The Blowfish key used for encrypting file headers.
    pub fn new(inner: W, default_key: [u8; 32], signature_key: [u8; 32]) -> io::Result<Self> {
        // Use current system time as timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| io::Error::other(format!("system time error: {e}")))?
            .as_secs() as i32;

        Ok(Self {
            inner,
            timestamp,
            flags: BitFlags::empty(), // Default no flags
            entries: Vec::new(),
            default_key,
            signature_key,
        })
    }

    /// Set the default Blowfish key used for encrypting file bodies.
    ///
    /// This is used in CTR mode with an IV derived from the entry metadata.
    pub const fn with_default_key(mut self, default_key: [u8; 32]) -> Self {
        self.default_key = default_key;
        self
    }

    /// Set the signature Blowfish key used for encrypting file headers.
    ///
    /// This is used in CTR mode with an IV derived from the entry metadata.
    pub const fn with_signature_key(mut self, signature_key: [u8; 32]) -> Self {
        self.signature_key = signature_key;
        self
    }

    /// Set the archive flags to write in the header.
    pub const fn with_flags(mut self, flags: BitFlags<ArchiveFlags>) -> Self {
        self.flags = flags;
        self
    }

    /// Set the timestamp of the archive.
    pub const fn with_timestamp(mut self, timestamp: i32) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn add_entry(
        &mut self,
        name_hash: AfsHash,
        compression: CompressionType,
        data: &[u8],
    ) -> io::Result<()> {
        let mut cursor = Cursor::new(data);
        self.add_entry_from_reader(name_hash, compression, &mut cursor)
    }

    pub fn add_entry_from_reader<R: Read + ?Sized>(
        &mut self,
        name_hash: AfsHash,
        compression: CompressionType,
        reader: &mut R,
    ) -> io::Result<()> {
        let uncompressed_size;

        // We'll capture an optional sha1 for encrypted entries here.
        let mut sha1_opt: Option<[u8; 20]> = None;

        let (compressed_data, actual_comp) = match compression {
            CompressionType::None => {
                let mut buf = Vec::new();
                uncompressed_size = reader.read_to_end(&mut buf)? as u32;
                (buf, CompressionType::None)
            }
            CompressionType::ZLib => {
                let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
                io::copy(reader, &mut enc)?;
                uncompressed_size = enc.total_in() as u32;
                (enc.finish()?, CompressionType::ZLib)
            }
            CompressionType::EdgeZLib => {
                let mut seg = SegmentedZlibWriter::new(Vec::new());
                uncompressed_size = io::copy(reader, &mut seg)? as u32;
                (seg.finish()?, CompressionType::EdgeZLib)
            }
            CompressionType::Encrypted => {
                // For encrypted entries: compress with EdgeZLib, compute SHA1 of the
                // original uncompressed data and store the checksum; we will build
                // the final (encrypted) payload later in `finish()` once offsets are
                // known and the IV can be forged.
                let mut buf = Vec::new();
                uncompressed_size = reader.read_to_end(&mut buf)? as u32;

                // compress with EdgeZLib
                let mut seg = SegmentedZlibWriter::new(Vec::new());
                seg.write_all(&buf)?;
                let compressed = seg.finish()?;

                // SHA1 checksum of uncompressed data
                let digest = sha1_smol::Sha1::from(&buf).digest().bytes();
                let mut checksum = [0u8; 20];
                checksum.copy_from_slice(&digest[..]);
                sha1_opt = Some(checksum);

                (compressed, CompressionType::Encrypted)
            }
        };

        // For encrypted entries the stored compressed_size on-disk includes the
        // 24-byte encrypted head + 4 bytes body-fourcc in addition to the
        // compressed body. Adjust compressed_size accordingly.
        let compressed_size = if actual_comp == CompressionType::Encrypted {
            (compressed_data.len() + 28) as u32
        } else {
            compressed_data.len() as u32
        };

        self.entries.push(BarEntryToWrite {
            name_hash,
            compression: actual_comp,
            uncompressed_size,
            compressed_size,
            data: compressed_data,
            offset: 0,
            sha1: sha1_opt,
        });

        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.calculate_offsets();

        // Offsets are already calculated (including per-entry padding) by `calculate_offsets()`
        // and stored in each entry's `offset` field. Do not overwrite them here.
        // Write Header
        let file_count = self.entries.len() as u32;

        // Write Magic
        self.inner.write_u32::<LittleEndian>(ARCHIVE_MAGIC)?;

        // Version and Flags
        let version = ArchiveVersion::BAR;
        let version_u16: u16 = version.into();
        let flags_u16 = self.flags.bits();

        let ver_flags = (u32::from(version_u16) << 16) | u32::from(flags_u16);
        self.inner.write_u32::<LittleEndian>(ver_flags)?;

        // Priority (0 default)
        self.inner.write_i32::<LittleEndian>(0)?;
        // Timestamp (0 default)
        self.inner.write_i32::<LittleEndian>(self.timestamp)?;
        // File Count
        self.inner.write_u32::<LittleEndian>(file_count)?;

        // Write ToC
        for entry in &self.entries {
            self.inner.write_i32::<LittleEndian>(entry.name_hash.0)?;

            let comp_val: u8 = entry.compression.into();
            let val = (entry.offset & 0xFFFFFFFC) | u32::from(comp_val);
            self.inner.write_u32::<LittleEndian>(val)?;

            self.inner
                .write_u32::<LittleEndian>(entry.uncompressed_size)?;
            self.inner
                .write_u32::<LittleEndian>(entry.compressed_size)?;
        }

        // For encrypted entries we need to build the encrypted payload now that
        // offsets and file_count are known (the IV depends on these values).
        for entry in &mut self.entries {
            if entry.compression == CompressionType::Encrypted
                && let Some(checksum) = entry.sha1
            {
                // Forge IV
                let iv = super::forge_iv(
                    u64::from(file_count),
                    u64::from(entry.uncompressed_size),
                    u64::from(entry.compressed_size),
                    u64::from(entry.offset),
                    self.timestamp,
                );

                // Build head: 4B fourcc (zeros) + 20B checksum
                let mut head = Vec::new();
                head.extend_from_slice(&[0u8; 4]);
                head.extend_from_slice(&checksum);

                // Encrypt head with signature_key using CryptoWriter
                let mut cw_head = CryptoWriter::new(
                    Vec::new(),
                    Ctr64BE::<Blowfish>::new(&self.signature_key.into(), &iv.into()),
                );
                cw_head.write_all(&head)?;
                let head_enc = cw_head.into_inner();

                // Encrypt body with default_key using IV + 3 via CryptoWriter
                let mut iv_as_u64 = u64::from_be_bytes(iv);
                iv_as_u64 = iv_as_u64.wrapping_add(3);
                let iv_body = iv_as_u64.to_be_bytes();

                let mut cw_body = CryptoWriter::new(
                    Vec::new(),
                    Ctr64BE::<Blowfish>::new(&self.default_key.into(), &iv_body.into()),
                );
                cw_body.write_all(&entry.data)?;
                let body_enc = cw_body.into_inner();

                // Body fourcc (4 bytes) - kept raw (zeros)
                let body_fourcc = [0u8; 4];

                // Compose final data: encrypted head, body_fourcc, encrypted body
                let mut final_data = Vec::new();
                final_data.extend_from_slice(&head_enc);
                final_data.extend_from_slice(&body_fourcc);
                final_data.extend_from_slice(&body_enc);

                entry.data = final_data;
            }

            self.inner.write_all(&entry.data)?;

            // Pad to 4 bytes if needed
            let pad_len = (4 - (entry.data.len() % 4)) % 4;
            if pad_len > 0 {
                self.inner.write_all(&vec![0u8; pad_len])?;
            }
        }

        Ok(self.inner)
    }
}

// Private helper for recalculating offsets
impl<W: Write> BarWriter<W> {
    fn calculate_offsets(&mut self) {
        let mut current_offset = 0;
        for entry in &mut self.entries {
            entry.offset = current_offset;

            let len = entry.compressed_size;
            let pad = (4 - (len % 4)) % 4;

            current_offset += len + pad;
        }
    }
}
