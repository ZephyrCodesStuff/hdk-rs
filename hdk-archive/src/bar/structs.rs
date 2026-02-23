use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom};

use binrw::binrw;
use ctr::{cipher::{KeyIvInit, StreamCipher}};
use flate2::read::ZlibDecoder;
use hdk_comp::zlib::reader::SegmentedZlibReader;
use hdk_secure::{hash::AfsHash, modes::BlowfishPS3};
use num_enum::TryFromPrimitive;

use crate::structs::{ArchiveVersion, CompressionType};

#[binrw]
#[brw(magic = 0xADEF17E1u32)] // For LE this will expect 0xE117EFAD, but binrw will handle that for us based on endianness
#[br(import(archive_key: [u8; 32], signature_key: [u8; 32], archive_size: u32))]
#[bw(import(archive_key: [u8; 32], signature_key: [u8; 32]))]
#[derive(Debug)]
pub struct BarArchive {
    // Version and Flags are a packed u32 where the upper 16 bits are version and lower 16 bits are flags.
    pub archive_info: BarArchiveMeta,
    pub archive_data: BarArchiveData,

    #[br(count = archive_data.file_count)]
    #[br(args { 
        // TODO: add support for ZTOC (changes the first one to 24)
        //       reminder: ZTOC is a ToC compressed with SegmentedZlib
        inner: (archive_data.timestamp, archive_data.file_count, 20 + (archive_data.file_count as u64 * 16), archive_size)
    })]
    pub entries: Vec<BarEntry>,
}

#[binrw]
#[derive(Copy, Clone, Debug)]
#[br(map = |x: u32| BarArchiveMeta { 
    version: (x >> 16) as u16, 
    flags: (x & 0xFFFF) as u16 
})]
#[bw(map = |x: &BarArchiveMeta| ((x.version as u32) << 16) | (x.flags as u32))]
pub struct BarArchiveMeta {
    #[br(assert(*version == ArchiveVersion::BAR.into(), "Unsupported BAR version"))]
    pub version: u16, // Upper 16 bits
    pub flags: u16,   // Lower 16 bits
}

#[binrw]
#[derive(Debug)]
pub struct BarArchiveData {
    /// Archives don't retain file paths, which means there might be collisions.
    /// 
    /// This field tells Home which archive to pick, when multiple archives have files with the same name hash.
    pub priority: i32,

    /// User-specific data.
    /// 
    /// PlayStation Home uses this to store a timestamp, but it could be repurposed for other things.
    pub timestamp: i32,

    /// Number of files in the archive
    pub file_count: u32,
}

#[binrw]
#[br(import(timestamp: i32, num_files: u32, data_start_pos: u64, archive_size: u32))]
#[derive(Debug)]
pub struct BarEntry {
    pub name_hash: AfsHash,

    #[br(try_map = |x: u32| {
        let offset = x & 0x3FFFFFFC; // Upper 30 bits
        let comp = (x & 0b11) as u8; // Lower 2 bits

        let pos = data_start_pos + offset as u64;

        if data_start_pos + offset as u64 > archive_size as u64 {
                Err(binrw::Error::AssertFail {
                    pos,
                    message: format!("File offset {offset} is out of bounds for archive size {archive_size} and data start position {data_start_pos}"),
                })
        } else {
            let comp_enum = CompressionType::try_from_primitive(comp)
                .map_err(|_| binrw::Error::AssertFail {
                    pos,
                    message: format!("Invalid compression type {comp} in entry with offset {offset}"),
                })?;

            Ok((offset, comp_enum))
        }
    })]
    #[bw(map = |(off, comp): &(u32, CompressionType)| *off | (*comp as u32 & 0x3))]
    pub location: (u32, CompressionType),

    pub uncompressed_size: u32,
    pub compressed_size: u32,

    // IV must be calculated for BAR entries.
    #[br(calc = super::forge_iv(num_files as u64, uncompressed_size as u64, compressed_size as u64, location.0 as u64, timestamp))]
    pub iv: [u8; 8],
}

impl BarArchive {
    /// Create a lazy reader for an entry that decompresses on-demand.
    /// 
    /// The reader holds references to the archive and entry, and will decompress
    /// the file data when read() is called.
    pub fn entry_data<'a>(
        &'a self,
        reader: &mut (impl Read + Seek),
        entry: &'a BarEntry,
        archive_key: &[u8; 32],
        signature_key: &[u8; 32],
    ) -> std::io::Result<Vec<u8>> {
        let data_start_pos = 20 + (self.entries.len() as u64 * 16);
        let (offset, comp_type) = entry.location;
        let entry_offset = data_start_pos + offset as u64;
        
        // Seek to entry and read compressed data
        reader.seek(SeekFrom::Start(entry_offset))?;
        let mut compressed = vec![0u8; entry.compressed_size as usize];
        reader.read_exact(&mut compressed)?;

        let iv = entry.iv;

        // Decompress based on type
        let decompressed = match comp_type {
            CompressionType::Encrypted => {
                if compressed.len() < 24 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Encrypted data too short",
                    ));
                }

                let (head, body_wrapper) = compressed.split_at(24);
                let mut head = head.to_vec();
                let mut body_wrapper = body_wrapper.to_vec();

                let mut bf = BlowfishPS3::new(signature_key.into(), &iv.into());
                bf.apply_keystream(&mut head);

                let mut iv_val = u64::from_be_bytes(iv);
                iv_val = iv_val.wrapping_add(3);
                let iv_body = iv_val.to_be_bytes();

                if body_wrapper.len() < 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Body too short"));
                }

                let (_fourcc, actual_body) = body_wrapper.split_at_mut(4);
                let mut bf_body = BlowfishPS3::new(archive_key.into(), &iv_body.into());
                bf_body.apply_keystream(actual_body);

                let seg = SegmentedZlibReader::new(Cursor::new(actual_body.to_vec()));
                let mut decompressed = Vec::new();
                BufReader::new(seg).read_to_end(&mut decompressed)?;
                decompressed
            }
            CompressionType::EdgeZLib => {
                let seg = SegmentedZlibReader::new(Cursor::new(compressed));
                let mut decompressed = Vec::new();
                BufReader::new(seg).read_to_end(&mut decompressed)?;
                decompressed
            }
            CompressionType::ZLib => {
                let decoder = ZlibDecoder::new(&compressed[..]);
                let mut decompressed = Vec::new();
                BufReader::new(decoder).read_to_end(&mut decompressed)?;
                decompressed
            }
            CompressionType::None => compressed,
        };
        
        Ok(decompressed)
    }
}