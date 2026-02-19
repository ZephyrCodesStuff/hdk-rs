use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use binrw::{BinReaderExt, Endian};
use ctr::Ctr128BE;
use enumflags2::BitFlag;
use flate2::read::ZlibDecoder;

use std::convert::TryFrom;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use hdk_comp::zlib::reader::SegmentedZlibReader;
use hdk_secure::{reader::CryptoReader, xtea::modes::XteaPS3};

use super::structs::{
    SharcEntry, SharcEntryMetadata, SharcHeader, SharcInnerHeader, SharcPreamble,
};
use crate::archive::ArchiveReader;
use crate::structs::{ARCHIVE_MAGIC, ArchiveFlags, CompressionType, Endianness};

pub struct SharcReader<R: Read + Seek> {
    /// The underlying reader.
    ///
    /// This is where the archive data is read from.
    inner: R,

    /// The parsed SHARC header.
    header: SharcHeader,

    /// Every entry in the archive's table of contents.
    entries: Vec<SharcEntry>,

    /// The detected endianness of the archive.
    pub endianness: Endianness,

    /// Where the raw file data starts in the archive.
    ///
    /// Offsets in entries are relative to this point.
    data_start_offset: u64,
}

impl<R: Read + Seek> SharcReader<R> {
    pub fn open(mut reader: R, key: [u8; 32]) -> io::Result<Self> {
        // 1. Detect Endianness via Magic
        let magic_val = reader.read_le::<u32>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read magic: {e}"),
            )
        })?;

        // Reset position to start so Preamble can read the magic field too
        reader.rewind()?;

        let endian = if magic_val == ARCHIVE_MAGIC {
            Endian::Little
        } else if magic_val.swap_bytes() == ARCHIVE_MAGIC {
            Endian::Big
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Magic"));
        };

        // 2. Read Preamble (Unencrypted)
        let preamble: SharcPreamble = reader.read_type(endian).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read SharcPreamble: {e}"),
            )
        })?;

        // 3. Prepare Decryption for Inner Header
        // Read raw encrypted bytes
        let mut header_buf = [0u8; 28]; // priority(4)+time(4)+count(4)+key(16)
        reader.read_exact(&mut header_buf)?;

        // Setup Cipher
        let mut cipher = Ctr128BE::<Aes256>::new(&key.into(), preamble.iv.as_slice().into());
        cipher.apply_keystream(&mut header_buf);

        // 4. Parse Inner Header
        // We use a Cursor on the decrypted buffer
        let mut cursor = Cursor::new(&header_buf);
        let inner: SharcInnerHeader = cursor.read_type(endian).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read SharcInnerHeader: {e}"),
            )
        })?;

        // 5. Read & Decrypt ToC
        let count = inner.file_count as usize;
        let toc_size = count * 24;
        let mut toc_buf = vec![0u8; toc_size];
        reader.read_exact(&mut toc_buf)?;

        // Previous cipher is now misaligned, so we have to create a new one.
        // Update IV (Increment by 1 for ToC)
        let mut iv_int = u128::from_be_bytes(preamble.iv.clone().try_into().unwrap());
        iv_int = iv_int.wrapping_add(1);

        let mut cipher_toc = Ctr128BE::<Aes256>::new(&key.into(), &iv_int.to_be_bytes().into());
        cipher_toc.apply_keystream(&mut toc_buf);

        // 6. Parse Entries
        let mut toc_cursor = Cursor::new(toc_buf);
        let entries: Vec<SharcEntry> = toc_cursor
            .read_type_args(endian, binrw::VecArgs { count, inner: () })
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to read SharcEntry ToC: {e}"),
                )
            })?;

        let data_start_offset = reader.stream_position()?;

        // 7. Assemble Public Header
        let header = SharcHeader {
            version: preamble.version_and_flags.0,
            flags: ArchiveFlags::from_bits_truncate(preamble.version_and_flags.1),
            iv: preamble.iv.try_into().unwrap(),
            priority: inner.priority,
            timestamp: inner.timestamp,
            file_count: inner.file_count,
            files_key: inner.files_key.try_into().unwrap(),
        };

        Ok(Self {
            inner: reader,
            header,
            entries,
            endianness: if endian == Endian::Little {
                Endianness::Little
            } else {
                Endianness::Big
            },
            data_start_offset,
        })
    }

    pub fn header(&self) -> SharcHeader {
        self.header.clone()
    }
    
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<R: Read + Seek> ArchiveReader for SharcReader<R> {
    type Metadata = SharcEntryMetadata;

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Return a copyable metadata view for an entry.
    fn entry_metadata(&self, index: usize) -> io::Result<SharcEntryMetadata> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Invalid entry index"))?;

        SharcEntryMetadata::try_from(entry).map_err(|()| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid entry IV length (expected 8 bytes)",
            )
        })
    }

    /// Returns a Reader that streams the file content, automatically handling
    /// decryption and decompression based on the entry type.
    fn entry_reader<'a>(&'a mut self, index: usize) -> io::Result<Box<dyn Read + 'a>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Invalid entry index"))?
            .clone();

        let start_offset = self.data_start_offset + entry.offset();
        self.inner.seek(SeekFrom::Start(start_offset))?;

        let raw_stream = (&mut self.inner).take(u64::from(entry.compressed_size));

        let comp_type = CompressionType::try_from(entry.compression()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown compression type in SharcEntry",
            )
        })?;

        match comp_type {
            // Encrypted: first compressed with ZLib, then encrypted with XTEA-CTR
            CompressionType::Encrypted => {
                // Decrypt with XTEA-CTR then stream-decompress with SegmentedZlibReader
                let key = self.header.files_key.into();
                let cipher = XteaPS3::new(&key, entry.iv.as_slice().into());
                let crypto = CryptoReader::new(raw_stream, cipher);
                let seg = SegmentedZlibReader::new(crypto);
                Ok(Box::new(seg))
            }

            // Standard ZLib compression
            CompressionType::ZLib => {
                let zlib = ZlibDecoder::new(raw_stream);
                Ok(Box::new(zlib))
            }

            // EdgeZLib (segmented zlib) -> if sizes match, it's actually an encrypted nested archive
            CompressionType::EdgeZLib if entry.compressed_size == entry.uncompressed_size => {
                let key = self.header.files_key.into();
                let cipher = XteaPS3::new(&key, entry.iv.as_slice().into());
                let crypto = CryptoReader::new(raw_stream, cipher);
                Ok(Box::new(crypto))
            }

            // EdgeZLib regular segmented streaming
            CompressionType::EdgeZLib => {
                let seg = SegmentedZlibReader::new(raw_stream);
                Ok(Box::new(seg))
            }

            // No compression
            CompressionType::None => Ok(Box::new(raw_stream)),
        }
    }
}
