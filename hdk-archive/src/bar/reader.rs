use super::structs::{BarEntry, BarEntryMetadata, BarHeader};

use crate::archive::ArchiveReader;
use crate::structs::{ARCHIVE_MAGIC, ArchiveFlags, ArchiveVersion, CompressionType, Endianness};

use binrw::{BinReaderExt, Endian};
use ctr::Ctr64BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use enumflags2::BitFlags;
use hdk_comp::zlib::reader::SegmentedZlibReader;
use hdk_secure::blowfish::Blowfish;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

pub struct BarReader<R: Read + Seek> {
    inner: R,
    header: BarHeader,
    entries: Vec<BarEntry>,
    toc_base: u64,
    flags: BitFlags<ArchiveFlags>,

    /// The detected endianness of the archive.
    pub endianness: Endianness,

    /// The default Blowfish key used for decrypting encrypted file bodies.
    ///
    /// This is used in CTR mode with an IV derived from the entry metadata.
    default_key: [u8; 32],

    /// The signature Blowfish key used for decrypting encrypted file headers.
    ///
    /// This is used in CTR mode with an IV derived from the entry metadata.
    signature_key: [u8; 32],
}

impl<R: Read + Seek> BarReader<R> {
    /// Open a BAR archive for reading.
    ///
    /// # Arguments
    ///
    /// * `reader` - The underlying reader to read the archive from.
    /// * `default_key` - The Blowfish key used for decrypting encrypted file bodies.
    /// * `signature_key` - The Blowfish key used for decrypting encrypted file headers.
    /// * `endianness` - Optional endianness (defaults to Little if None).
    pub fn open(mut reader: R, default_key: [u8; 32], signature_key: [u8; 32], endianness: Option<Endianness>) -> io::Result<Self> {
        // Determine endianness (default to Little)
        let endianness = endianness.unwrap_or(Endianness::Little);
        
        // Convert to binrw::Endian using the From trait
        let endian: Endian = endianness.into();

        let magic_val = reader
            .read_type::<u32>(endian)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if magic_val != ARCHIVE_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid BAR magic",
            ));
        }

        // Read fixed header part
        let header: BarHeader = reader
            .read_type(endian)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Convert tuple to actual types
        let version_val = header.version_and_flags.0;
        let flags_val = header.version_and_flags.1;

        let version = ArchiveVersion::try_from(version_val)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid BAR version"))?;

        if version != ArchiveVersion::BAR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected BAR version, got {version:?}"),
            ));
        }

        let flags = BitFlags::<ArchiveFlags>::from_bits_truncate(flags_val);

        let entries_count = header.file_count as usize;
        let entries_size = (entries_count as u64) * 16;

        // Handle ZTOC
        let (toc_data, toc_base) = if flags.contains(ArchiveFlags::ZTOC) {
            let compressed_size = reader
                .read_type::<u32>(endian)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut compressed_data = vec![0u8; compressed_size as usize];
            reader.read_exact(&mut compressed_data)?;

            // Decompress ZTOC
            let mut d = flate2::Decompress::new(false);
            let mut toc_data = Vec::with_capacity(entries_size as usize);
            d.decompress_vec(
                &compressed_data,
                &mut toc_data,
                flate2::FlushDecompress::Finish,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            (toc_data, 24 + u64::from(compressed_size))
        } else {
            let mut toc_data = vec![0u8; entries_size as usize];
            reader.read_exact(&mut toc_data)?;

            (toc_data, 20 + entries_size)
        };

        let mut cursor = Cursor::new(toc_data);
        let mut entries = Vec::with_capacity(entries_count);

        for _ in 0..entries_count {
            let mut entry: BarEntry = cursor
                .read_type(endian)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Fixup compression type bug (0 vs 1)
            let comp = entry.compression();
            if comp == CompressionType::None && entry.compressed_size < entry.uncompressed_size {
                entry.offset_and_comp.1 = CompressionType::ZLib.into();
            } else if comp == CompressionType::ZLib
                && entry.compressed_size == entry.uncompressed_size
            {
                entry.offset_and_comp.1 = CompressionType::None.into();
            }
            entries.push(entry);
        }

        Ok(Self {
            inner: reader,
            header,
            entries,
            toc_base,
            flags,
            endianness,
            default_key,
            signature_key,
        })
    }

    pub fn header(&self) -> BarHeader {
        self.header.clone()
    }
}

impl<R: Read + Seek> ArchiveReader for BarReader<R> {
    type Metadata = BarEntryMetadata;

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn entry_metadata(&self, index: usize) -> io::Result<BarEntryMetadata> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Invalid entry index"))?;
        Ok(entry.into())
    }

    fn entry_reader<'a>(&'a mut self, index: usize) -> io::Result<Box<dyn Read + 'a>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Index out of bounds"))?;

        let offset = u64::from(entry.offset());
        let abs_offset = self.toc_base + offset;

        self.inner.seek(SeekFrom::Start(abs_offset))?;
        let mut raw_data = vec![0u8; entry.compressed_size as usize];
        self.inner.read_exact(&mut raw_data)?;

        let comp_type = entry.compression();
        let use_zlib_header = !self.flags.contains(ArchiveFlags::LeanZLib);

        match comp_type {
            CompressionType::Encrypted => {
                let iv = super::forge_iv(
                    u64::from(self.header.file_count),
                    u64::from(entry.uncompressed_size),
                    u64::from(entry.compressed_size),
                    u64::from(entry.offset()),
                    self.header.timestamp,
                );

                if raw_data.len() < 24 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Encrypted data too short",
                    ));
                }

                let (head, body_wrapper) = raw_data.split_at(24);
                let mut head = head.to_vec();
                let mut body_wrapper = body_wrapper.to_vec();

                type BlowfishCtr = Ctr64BE<Blowfish>;
                let mut bf = BlowfishCtr::new(&self.signature_key.into(), &iv.into());
                bf.apply_keystream(&mut head);

                let mut iv_val = u64::from_be_bytes(iv);
                iv_val = iv_val.wrapping_add(3);
                let iv_body = iv_val.to_be_bytes();

                if body_wrapper.len() < 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Body too short"));
                }

                let (_fourcc, actual_body) = body_wrapper.split_at_mut(4);
                let mut bf_body = BlowfishCtr::new(&self.default_key.into(), &iv_body.into());
                bf_body.apply_keystream(actual_body);

                let seg = SegmentedZlibReader::new(Cursor::new(actual_body.to_vec()));
                Ok(Box::new(seg))
            }
            CompressionType::EdgeZLib => {
                let seg = SegmentedZlibReader::new(Cursor::new(raw_data));
                Ok(Box::new(seg))
            }
            _ => {
                let data = decompress_data_helper(&raw_data, comp_type, use_zlib_header)?;
                Ok(Box::new(Cursor::new(data)))
            }
        }
    }
}

fn decompress_data_helper(
    data: &[u8],
    ctype: CompressionType,
    zlib_header: bool,
) -> io::Result<Vec<u8>> {
    match ctype {
        CompressionType::None => Ok(data.to_vec()),
        CompressionType::ZLib => {
            if zlib_header {
                let mut d = flate2::read::ZlibDecoder::new(data);
                let mut out = Vec::new();
                d.read_to_end(&mut out)?;
                Ok(out)
            } else {
                let mut d = flate2::Decompress::new(zlib_header);
                let mut out = Vec::new();
                d.decompress_vec(data, &mut out, flate2::FlushDecompress::None)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(out)
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unsupported or Handled Elsewhere",
        )),
    }
}
