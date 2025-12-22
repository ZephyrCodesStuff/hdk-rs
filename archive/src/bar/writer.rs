use byteorder::{LittleEndian, WriteBytesExt};
use enumflags2::BitFlags;
use flate2::{Compression, write::ZlibEncoder};
use std::io::{self, Cursor, Read, Seek, Write};

use comp::zlib::writer::SegmentedZlibWriter;

use crate::structs::{ARCHIVE_MAGIC, ArchiveFlags, ArchiveVersion, CompressionType};

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

    pub fn add_entry_from_reader<R: Read + ?Sized>(
        &mut self,
        name_hash: i32,
        compression: CompressionType,
        reader: &mut R,
    ) -> io::Result<()> {
        let uncompressed_size;

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
                unimplemented!("BAR writer does not support encrypted compression yet")
            }
        };

        self.entries.push(BarEntryToWrite {
            name_hash,
            compression: actual_comp,
            uncompressed_size,
            compressed_size: compressed_data.len() as u32,
            data: compressed_data,
            offset: 0,
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

        for entry in &self.entries {
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
