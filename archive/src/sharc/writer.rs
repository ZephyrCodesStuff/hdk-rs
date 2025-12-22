use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use ctr::Ctr128BE;
use flate2::{Compression, write::ZlibEncoder};
use rand::RngCore;
use std::io::{self, Read, Write};

use comp::zlib::writer::SegmentedZlibWriter;
use secure::xtea::modes::XteaPS3;

use crate::structs::{ARCHIVE_MAGIC, CompressionType, Endianness};

/// Helper small struct to hold a queued entry for writing
struct EntryToWrite {
    name_hash: u32,
    compression: CompressionType,
    uncompressed_size: u32,
    compressed_size: u32,
    iv: [u8; 8],
    data: Vec<u8>,
    offset: u32,
}

pub struct SharcWriter<W: Write> {
    inner: W,
    key: [u8; 32],
    endianness: Endianness,

    // Header fields
    pub version: u16,
    pub flags: u16,
    pub iv: [u8; 16],

    pub priority: i32,
    pub timestamp: i32,

    pub files_key: [u8; 16],

    entries: Vec<EntryToWrite>,
}

impl<W: Write> SharcWriter<W> {
    pub fn new(inner: W, key: [u8; 32], endianness: Endianness) -> io::Result<Self> {
        let mut rng = rand::rng();
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);

        let mut files_key = [0u8; 16];
        rng.fill_bytes(&mut files_key);

        Ok(Self {
            inner,
            key,
            endianness,
            version: 1,
            flags: 0,
            iv,
            priority: 0,
            timestamp: 0,
            files_key,
            entries: Vec::new(),
        })
    }

    /// Add an entry from a byte slice.
    pub fn add_entry_from_bytes(
        &mut self,
        name_hash: u32,
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
        name_hash: u32,
        compression: CompressionType,
        mut reader: &mut Rd,
    ) -> io::Result<()>
    where
        Rd: Read,
    {
        let mut uncompressed_size: u32 = 0;

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
            let mut cipher = XteaPS3::new(&key_ga, iv.as_slice().into());
            cipher.apply_keystream(&mut data);
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
        const PREAMBLE_SIZE: usize = 4 + 4 + 16; // magic + ver/flags + iv
        const INNER_SIZE: usize = 4 + 4 + 4 + 16; // priority + timestamp + file_count + files_key
        const HEADER_TOTAL: usize = PREAMBLE_SIZE + INNER_SIZE; // 52

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
        match self.endianness {
            Endianness::Little => {
                self.inner.write_u32::<LittleEndian>(ARCHIVE_MAGIC)?;
                let flags_and_version = ((self.version as u32) << 16) | (self.flags as u32);
                self.inner.write_u32::<LittleEndian>(flags_and_version)?;
            }
            Endianness::Big => {
                self.inner.write_u32::<BigEndian>(ARCHIVE_MAGIC)?;
                let flags_and_version = ((self.version as u32) << 16) | (self.flags as u32);
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

        // Encrypt inner_buf with AES-256 CTR using iv
        let mut cipher = Ctr128BE::<Aes256>::new(&self.key.into(), self.iv.as_slice().into());
        cipher.apply_keystream(&mut inner_buf);
        self.inner.write_all(&inner_buf)?;

        // 3) Build ToC (plain) then encrypt with iv+1
        let mut toc_buf: Vec<u8> = Vec::with_capacity(toc_size);
        for e in &self.entries {
            match self.endianness {
                Endianness::Little => {
                    toc_buf.write_u32::<LittleEndian>(e.name_hash)?;
                    let offset_and_comp = (e.offset & 0xFFFFFFFC) | (e.compression as u32);
                    toc_buf.write_u32::<LittleEndian>(offset_and_comp)?;
                    toc_buf.write_u32::<LittleEndian>(e.uncompressed_size)?;
                    toc_buf.write_u32::<LittleEndian>(e.compressed_size)?;
                }
                Endianness::Big => {
                    toc_buf.write_u32::<BigEndian>(e.name_hash)?;
                    let offset_and_comp = (e.offset & 0xFFFFFFFC) | (e.compression as u32);
                    toc_buf.write_u32::<BigEndian>(offset_and_comp)?;
                    toc_buf.write_u32::<BigEndian>(e.uncompressed_size)?;
                    toc_buf.write_u32::<BigEndian>(e.compressed_size)?;
                }
            }
            toc_buf.extend_from_slice(&e.iv);
        }

        // Encrypt ToC with iv + 1
        let mut iv_int = u128::from_be_bytes(self.iv);
        iv_int = iv_int.wrapping_add(1);
        let iv_inc = iv_int.to_be_bytes();
        let mut toc_cipher = Ctr128BE::<Aes256>::new(&self.key.into(), &iv_inc.into());
        toc_cipher.apply_keystream(&mut toc_buf);
        self.inner.write_all(&toc_buf)?;

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
