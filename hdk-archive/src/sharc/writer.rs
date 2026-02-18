use aes::Aes256;
use aes::cipher::KeyIvInit;
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use ctr::Ctr128BE;
use enumflags2::{BitFlag, BitFlags};
use flate2::{Compression, write::ZlibEncoder};
use rand::RngCore;
use std::io::{self, Read, Write};

use hdk_comp::zlib::writer::SegmentedZlibWriter;
use hdk_secure::{hash::AfsHash, xtea::modes::XteaPS3};

use crate::structs::{ARCHIVE_MAGIC, ArchiveFlags, ArchiveVersion, CompressionType, Endianness};

/// Helper small struct to hold a queued entry for writing
struct EntryToWrite {
    name_hash: AfsHash,
    compression: CompressionType,
    uncompressed_size: u32,
    compressed_size: u32,
    iv: [u8; 8],
    data: Vec<u8>,
    offset: u32,
}

pub struct SharcWriter<W: Write> {
    inner: W,

    /// SHARC header and ToC encryption key.
    ///
    /// This one is canonically one of two keys:
    /// - The core / default key, used for the game's core archives (such as `COREDATA.SHARC`)
    /// - The CDN / content key, used for any SHARC embedded in CDN-downloaded SDAT files.
    key: [u8; 32],

    /// Home archives can be either big-endian or little-endian.
    ///
    /// The canonical default for SHARC is big-endian.
    endianness: Endianness,

    /// This holds Home archives bitflags.
    pub flags: BitFlags<ArchiveFlags>,

    /// This can be any random 16 bytes.
    pub iv: [u8; 16],

    /// Priority field in the inner header.
    ///
    /// Home uses this to choose which archive has precedence when loading files
    /// with conflicting name hashes.
    ///
    /// Set this to `0` for standard archives.
    pub priority: i32,

    /// Contrarily to what the name suggests, this is often random bytes
    /// in original Home archives.
    ///
    /// `hdk-rs` will, however, use the device's local time as a timestamp here.
    pub timestamp: i32,

    /// The XTEA key used to encrypt file entries.
    ///
    /// This can be any random 16 bytes.
    pub files_key: [u8; 16],

    /// The list of entries to write.
    entries: Vec<EntryToWrite>,
}

impl Default for SharcWriter<std::io::Cursor<Vec<u8>>> {
    fn default() -> Self {
        Self::new(std::io::Cursor::new(Vec::new()), [0u8; 32], Endianness::Big).unwrap()
    }
}

impl<W: Write> SharcWriter<W> {
    /// Set the SHARC header and ToC encryption key.
    ///
    /// This should only be set to one of two keys:
    /// - The core / default key, used for the game's core archives (such as `COREDATA.SHARC`)
    /// - The CDN / content key, used for any SHARC embedded in CDN-downloaded SDAT files.
    ///
    /// Setting a wrong key will render the game unable to read the archive.
    pub const fn with_key(mut self, key: [u8; 32]) -> Self {
        self.key = key;
        self
    }

    /// Set the endianness of the archive.
    ///
    /// Canonical SHARC archives are big-endian, but Home archives can be either.
    pub const fn with_endianess(mut self, endianness: Endianness) -> Self {
        self.endianness = endianness;
        self
    }

    /// Set the timestamp of the archive.
    ///
    /// This is often random bytes in original Home archives,
    /// but `hdk-rs` uses the device's local time by default.
    pub const fn with_timestamp(mut self, timestamp: i32) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Sets the flags of the archive.
    pub const fn with_flags(mut self, flags: BitFlags<ArchiveFlags>) -> Self {
        self.flags = flags;
        self
    }

    pub fn new(inner: W, key: [u8; 32], endianness: Endianness) -> io::Result<Self> {
        let mut rng = rand::rng();
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);

        let mut files_key = [0u8; 16];
        rng.fill_bytes(&mut files_key);

        // Use current system time as timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| io::Error::other(format!("system time error: {e}")))?
            .as_secs() as i32;

        Ok(Self {
            inner,
            key,
            endianness,
            flags: ArchiveFlags::empty(),
            iv,
            priority: 0,
            timestamp,
            files_key,
            entries: Vec::new(),
        })
    }

    /// Add an entry from a byte slice.
    pub fn add_entry_from_bytes(
        &mut self,
        name_hash: AfsHash,
        compression: CompressionType,
        bytes: &[u8],
    ) -> io::Result<()> {
        let mut cur = std::io::Cursor::new(bytes);
        self.add_entry_from_reader(name_hash, compression, &mut cur)
    }

    /// Streaming variant: read data from `reader`, compress/encrypt as needed and store entry.
    /// This avoids requiring callers to provide the entire content as a single slice.
    pub fn add_entry_from_reader<Rd: Read + ?Sized>(
        &mut self,
        name_hash: AfsHash,
        compression: CompressionType,
        mut reader: &mut Rd,
    ) -> io::Result<()> {
        let uncompressed_size;

        let data: Vec<u8> = match compression {
            CompressionType::None => {
                let mut buf = Vec::new();
                let n = reader.read_to_end(&mut buf)?;
                uncompressed_size = n as u32;
                buf
            }

            CompressionType::ZLib => {
                let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
                let n = std::io::copy(&mut reader, &mut enc)?;
                uncompressed_size = n as u32;
                enc.finish()?
            }

            CompressionType::EdgeZLib | CompressionType::Encrypted => {
                let mut seg = SegmentedZlibWriter::new(Vec::new());
                let n = std::io::copy(&mut reader, &mut seg)?;
                uncompressed_size = n as u32;
                seg.finish()?
            }
        };

        // For Encrypted, encrypt compressed buffer using XTEA-CTR with files_key
        let mut iv = [0u8; 8];
        let mut data = data;
        if compression == CompressionType::Encrypted {
            let mut rng = rand::rng();
            rng.fill_bytes(&mut iv);

            let key_ga = self.files_key.into();
            // Use CryptoWriter so encryption is clearly expressed and reusable
            let mut cw = hdk_secure::writer::CryptoWriter::new(
                Vec::new(),
                XteaPS3::new(&key_ga, iv.as_slice().into()),
            );
            cw.write_all(&data)?;
            data = cw.into_inner();
        }

        let compressed_size = data.len() as u32;

        self.entries.push(EntryToWrite {
            name_hash,
            compression,
            uncompressed_size,
            compressed_size,
            iv,
            data,
            offset: 0,
        });

        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        // Header sizes
        const INNER_SIZE: usize = 4 + 4 + 4 + 16; // priority + timestamp + file_count + files_key

        let file_count = self.entries.len() as u32;
        let toc_size = (file_count as usize) * 24;

        // Compute offsets (relative to the start of the data section).
        // The reader interprets entry offsets as `data_start_offset + entry.offset()`.
        let mut current_data_offset: u32 = 0;
        for e in &mut self.entries {
            e.offset = current_data_offset;
            current_data_offset = current_data_offset
                .checked_add(e.compressed_size)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Size overflow"))?;

            // 4-byte alignment padding
            let padding = (4 - (e.compressed_size as usize % 4)) % 4;
            current_data_offset = current_data_offset
                .checked_add(padding as u32)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Size overflow"))?;
        }

        // 1) Write Preamble (plain)
        let version = ArchiveVersion::SHARC as u16;
        match self.endianness {
            Endianness::Little => {
                self.inner.write_u32::<LittleEndian>(ARCHIVE_MAGIC)?;
                let flags_and_version = (u32::from(version) << 16) | u32::from(self.flags.bits());
                self.inner.write_u32::<LittleEndian>(flags_and_version)?;
            }
            Endianness::Big => {
                self.inner.write_u32::<BigEndian>(ARCHIVE_MAGIC)?;
                let flags_and_version = (u32::from(version) << 16) | u32::from(self.flags.bits());
                self.inner.write_u32::<BigEndian>(flags_and_version)?;
            }
        }
        self.inner.write_all(&self.iv)?;

        // 2) Inner header (encrypt with AES-CTR using `key` and `iv`)
        let mut inner_buf = Vec::with_capacity(INNER_SIZE);
        match self.endianness {
            Endianness::Little => {
                inner_buf.write_i32::<LittleEndian>(self.priority)?;
                inner_buf.write_i32::<LittleEndian>(self.timestamp)?;
                inner_buf.write_u32::<LittleEndian>(file_count)?;
            }
            Endianness::Big => {
                inner_buf.write_i32::<BigEndian>(self.priority)?;
                inner_buf.write_i32::<BigEndian>(self.timestamp)?;
                inner_buf.write_u32::<BigEndian>(file_count)?;
            }
        }
        inner_buf.extend_from_slice(&self.files_key);

        // Encrypt inner_buf with AES-256 CTR using iv using CryptoWriter
        let mut cw = hdk_secure::writer::CryptoWriter::new(
            Vec::new(),
            Ctr128BE::<Aes256>::new(&self.key.into(), self.iv.as_slice().into()),
        );
        cw.write_all(&inner_buf)?;
        let enc_inner = cw.into_inner();
        self.inner.write_all(&enc_inner)?;

        // 3) Build ToC (plain) then encrypt with iv+1
        let mut toc_buf: Vec<u8> = Vec::with_capacity(toc_size);
        for e in &self.entries {
            match self.endianness {
                Endianness::Little => {
                    toc_buf.write_i32::<LittleEndian>(e.name_hash.0)?;
                    let offset_and_comp = (e.offset & 0xFFFFFFFC) | (e.compression as u32);
                    toc_buf.write_u32::<LittleEndian>(offset_and_comp)?;
                    toc_buf.write_u32::<LittleEndian>(e.uncompressed_size)?;
                    toc_buf.write_u32::<LittleEndian>(e.compressed_size)?;
                }
                Endianness::Big => {
                    toc_buf.write_i32::<BigEndian>(e.name_hash.0)?;
                    let offset_and_comp = (e.offset & 0xFFFFFFFC) | (e.compression as u32);
                    toc_buf.write_u32::<BigEndian>(offset_and_comp)?;
                    toc_buf.write_u32::<BigEndian>(e.uncompressed_size)?;
                    toc_buf.write_u32::<BigEndian>(e.compressed_size)?;
                }
            }
            toc_buf.extend_from_slice(&e.iv);
        }

        // Encrypt ToC with iv + 1 using CryptoWriter
        let mut iv_int = u128::from_be_bytes(self.iv);
        iv_int = iv_int.wrapping_add(1);
        let iv_inc = iv_int.to_be_bytes();
        let mut toc_cw = hdk_secure::writer::CryptoWriter::new(
            Vec::new(),
            Ctr128BE::<Aes256>::new(&self.key.into(), &iv_inc.into()),
        );
        toc_cw.write_all(&toc_buf)?;
        let enc_toc = toc_cw.into_inner();
        self.inner.write_all(&enc_toc)?;

        // 4) Entries data + padding
        let mut rng = rand::rng();

        for e in &self.entries {
            self.inner.write_all(&e.data)?;
            let padding = (4 - (e.data.len() % 4)) % 4;
            if padding > 0 {
                let mut pad = vec![0u8; padding];
                rng.fill_bytes(&mut pad);
                self.inner.write_all(&pad)?;
            }
        }

        Ok(self.inner)
    }
}
