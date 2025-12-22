use byteorder::{LittleEndian, WriteBytesExt};
use enumflags2::BitFlags;
use flate2::{Compression, write::ZlibEncoder};
use std::io::{self, Cursor, Read, Seek, Write};

use comp::zlib::writer::SegmentedZlibWriter;
use ctr::Ctr64BE;
use ctr::cipher::KeyIvInit;
use secure::blowfish::Blowfish;
use secure::writer::CryptoWriter;

use crate::structs::{ARCHIVE_MAGIC, ArchiveFlags, ArchiveVersion, CompressionType};

const DEFAULT_KEY: [u8; 32] = [
    0x80, 0x6D, 0x79, 0x16, 0x23, 0x42, 0xA1, 0x0E, 0x8F, 0x78, 0x14, 0xD4, 0xF9, 0x94, 0xA2, 0xD1,
    0x74, 0x13, 0xFC, 0xA8, 0xF6, 0xE0, 0xB8, 0xA4, 0xED, 0xB9, 0xDC, 0x32, 0x7F, 0x8B, 0xA7, 0x11,
];
const SIGNATURE_KEY: [u8; 32] = [
    0xEF, 0x8C, 0x7D, 0xE8, 0xE5, 0xD5, 0xD6, 0x1D, 0x6A, 0xAA, 0x5A, 0xCA, 0xF7, 0xC1, 0x6F, 0xC4,
    0x5A, 0xFC, 0x59, 0xE4, 0x8F, 0xE6, 0xC5, 0x93, 0x7E, 0xBD, 0xFF, 0xC1, 0xE3, 0x99, 0x9E, 0x62,
];

pub struct BarWriter<W: Write> {
    inner: W,
    flags: BitFlags<ArchiveFlags>,
    entries: Vec<BarEntryToWrite>,
}

struct BarEntryToWrite {
    name_hash: i32,
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

impl<W: Write + Seek> BarWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            flags: BitFlags::empty(), // Default no flags
            entries: Vec::new(),
        }
    }

    pub fn with_flags(mut self, flags: BitFlags<ArchiveFlags>) -> Self {
        self.flags = flags;
        self
    }

    pub fn add_entry(
        &mut self,
        name_hash: i32,
        compression: CompressionType,
        data: &[u8],
    ) -> io::Result<()> {
        let mut cursor = Cursor::new(data);
        self.add_entry_from_reader(name_hash, compression, &mut cursor)
    }

    // Helper to forge IV matching the reader's implementation.
    fn forge_iv(
        num_files: u64,
        uncomp_size: u64,
        comp_size: u64,
        offset: u64,
        timestamp: i32,
    ) -> [u8; 8] {
        let extended_timestamp = 0xFFFFFFFF00000000u64 | (timestamp as u64);
        let val = (uncomp_size << 0x30)
            | ((comp_size & 0xFFFF) << 0x20)
            | (((offset + 20 + (num_files * 16)) & 0x3FFFC) << 0xE)
            | (extended_timestamp & 0xFFFF);
        val.to_be_bytes()
    }

    pub fn add_entry_from_reader<R: Read + ?Sized>(
        &mut self,
        name_hash: i32,
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

        let ver_flags = ((version_u16 as u32) << 16) | (flags_u16 as u32);
        self.inner.write_u32::<LittleEndian>(ver_flags)?;

        // Priority (0 default)
        self.inner.write_i32::<LittleEndian>(0)?;
        // Timestamp (0 default)
        // TODO: support custom timestamp
        self.inner.write_i32::<LittleEndian>(0)?;
        // File Count
        self.inner.write_u32::<LittleEndian>(file_count)?;

        // Write ToC
        for entry in &self.entries {
            self.inner.write_i32::<LittleEndian>(entry.name_hash)?;

            let comp_val: u8 = entry.compression.into();
            let val = (entry.offset & 0xFFFFFFFC) | (comp_val as u32);
            self.inner.write_u32::<LittleEndian>(val)?;

            self.inner
                .write_u32::<LittleEndian>(entry.uncompressed_size)?;
            self.inner
                .write_u32::<LittleEndian>(entry.compressed_size)?;
        }

        // For encrypted entries we need to build the encrypted payload now that
        // offsets and file_count are known (the IV depends on these values).
        for entry in &mut self.entries {
            if entry.compression == CompressionType::Encrypted {
                if let Some(checksum) = entry.sha1 {
                    // Forge IV
                    let iv = Self::forge_iv(
                        file_count as u64,
                        entry.uncompressed_size as u64,
                        entry.compressed_size as u64,
                        entry.offset as u64,
                        0, // timestamp currently 0
                    );

                    // Build head: 4B fourcc (zeros) + 20B checksum
                    let mut head = Vec::new();
                    head.extend_from_slice(&[0u8; 4]);
                    head.extend_from_slice(&checksum);

                    // Encrypt head with SIGNATURE_KEY using CryptoWriter
                    let mut cw_head = CryptoWriter::new(
                        Vec::new(),
                        Ctr64BE::<Blowfish>::new(&SIGNATURE_KEY.into(), &iv.into()),
                    );
                    cw_head.write_all(&head)?;
                    let head_enc = cw_head.into_inner();

                    // Encrypt body with DEFAULT_KEY using IV + 3 via CryptoWriter
                    let mut iv_as_u64 = u64::from_be_bytes(iv);
                    iv_as_u64 = iv_as_u64.wrapping_add(3);
                    let iv_body = iv_as_u64.to_be_bytes();

                    let mut cw_body = CryptoWriter::new(
                        Vec::new(),
                        Ctr64BE::<Blowfish>::new(&DEFAULT_KEY.into(), &iv_body.into()),
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
impl<W: Write + Seek> BarWriter<W> {
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
