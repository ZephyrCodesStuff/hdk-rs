use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use binrw::{BinReaderExt, Endian};
use ctr::Ctr128BE;
use std::convert::TryFrom;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use comp::zlib::reader::SegmentedZlibReader;
use flate2::read::ZlibDecoder;
use secure::reader::CryptoReader;
use secure::xtea::modes::XteaPS3;

use super::structs::{
    SharcEntry, SharcEntryMetadata, SharcHeader, SharcInnerHeader, SharcPreamble,
};
use crate::structs::{ARCHIVE_MAGIC, CompressionType, Endianness}; // Your common structs

pub struct SharcArchive<R: Read + Seek> {
    inner: R,
    pub header: SharcHeader,
    entries: Vec<SharcEntry>,
    pub endianness: Endianness,
    data_start_offset: u64,
}

impl<R: Read + Seek> SharcArchive<R> {
    pub fn open(mut reader: R, key: [u8; 32]) -> io::Result<Self> {
        // 1. Detect Endianness via Magic
        let magic_val = reader.read_le::<u32>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read magic: {}", e),
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
                format!("Failed to read SharcPreamble: {}", e),
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
                format!("Failed to read SharcInnerHeader: {}", e),
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
                    format!("Failed to read SharcEntry ToC: {}", e),
                )
            })?;

        let data_start_offset = reader.stream_position()?;

        // 7. Assemble Public Header
        let header = SharcHeader {
            version: preamble.version_and_flags.0,
            flags: preamble.version_and_flags.1,
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

    /// Number of entries in the archive.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrow the raw parsed table-of-contents entries.
    ///
    /// Prefer `entries_metadata()` if you want a stable, copyable metadata view.
    pub fn entries(&self) -> &[SharcEntry] {
        &self.entries
    }

    /// Borrow a single raw entry.
    pub fn entry(&self, index: usize) -> Option<&SharcEntry> {
        self.entries.get(index)
    }

    /// Return a copyable metadata view for an entry.
    pub fn entry_metadata(&self, index: usize) -> io::Result<SharcEntryMetadata> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Invalid entry index"))?;

        SharcEntryMetadata::try_from(entry).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid entry IV length (expected 8 bytes)",
            )
        })
    }

    /// Iterate copyable metadata for all entries.
    ///
    /// Items are `io::Result<_>` because malformed IV lengths are possible.
    pub fn entries_metadata(&self) -> impl Iterator<Item = io::Result<SharcEntryMetadata>> + '_ {
        self.entries.iter().map(|e| {
            SharcEntryMetadata::try_from(e).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid entry IV length (expected 8 bytes)",
                )
            })
        })
    }

    /// Find the first entry index with a matching `name_hash`.
    pub fn find_entry(&self, name_hash: u32) -> Option<usize> {
        self.entries.iter().position(|e| e.name_hash == name_hash)
    }

    /// Returns a Reader that streams the file content, automatically handling
    /// decryption and decompression based on the entry type.
    pub fn entry_reader<'a>(&'a mut self, index: usize) -> io::Result<Box<dyn Read + 'a>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Invalid entry index"))?
            .clone();

        let start_offset = self.data_start_offset + entry.offset();
        self.inner.seek(SeekFrom::Start(start_offset))?;

        let raw_stream = (&mut self.inner).take(entry.compressed_size as u64);

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
            _ => Ok(Box::new(raw_stream)),
        }
    }
}
