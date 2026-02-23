use std::{io::{BufReader, Read, Seek, SeekFrom}};

use binrw::{BinRead, BinWrite, binrw};
use ctr::cipher::{KeyIvInit};
use flate2::{read::ZlibDecoder};
use hdk_comp::zlib::{reader::SegmentedZlibReader};
use hdk_secure::{hash::AfsHash, modes::XteaPS3, reader::CryptoReader};
use num_enum::TryFromPrimitive;

use super::cryptor::SharcCryptor;
use crate::structs::CompressionType;

#[binrw]
#[brw(magic = 0xADEF17E1u32)] // For LE this will expect 0xE117EFAD, but binrw will handle that for us based on endianness
#[br(import(archive_key: [u8; 32], archive_size: u32))]
#[bw(import(archive_key: [u8; 32]))]
#[derive(Debug)]
pub struct SharcArchive {
    // Magic is 4 bytes and is either ADEF17E1 for BE or E117EFAD for LE

    // Version and Flags are a packed u32 where the upper 16 bits are version and lower 16 bits are flags.
    pub archive_info: SharcArchiveMeta,

    // Used to decrypt the ArchiveData
    pub iv: [u8; 16],

    #[br(map_stream = |r| SharcCryptor::new(r, &archive_key, &iv))]
    #[bw(map_stream = |w| SharcCryptor::new(w, &archive_key, iv))]
    pub archive_data: SharcArchiveData,

    #[br(count = archive_data.file_count)]
    #[br(map_stream = |r| {
        let current_iv = u128::from_be_bytes(iv);
        let next_iv = current_iv.wrapping_add(1).to_be_bytes();

        SharcCryptor::new(r, &archive_key, &next_iv)
    })]
    #[bw(map_stream = |w| {
        let current_iv = u128::from_be_bytes(*iv);
        let next_iv = current_iv.wrapping_add(1).to_be_bytes();

        SharcCryptor::new(w, &archive_key, &next_iv)
    })]
    #[br(args { 
        inner: (archive_size, 52 + (archive_data.file_count as u64 * 24))
    })]
    pub entries: Vec<SharcEntry>,
}

#[derive(BinRead, BinWrite, Copy, Clone, Debug)]
#[br(map = |x: u32| SharcArchiveMeta { 
    version: (x >> 16) as u16, 
    flags: (x & 0xFFFF) as u16 
})]
#[bw(map = |x: &SharcArchiveMeta| ((x.version as u32) << 16) | (x.flags as u32))]
pub struct SharcArchiveMeta {
    #[br(assert(*version == 512, "Unsupported SHARC version"))]
    pub version: u16, // Upper 16 bits
    pub flags: u16,   // Lower 16 bits
}

#[binrw]
#[derive(Debug)]
pub struct SharcArchiveData {
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

    /// Key used to encrypt files
    pub key: [u8; 16],
}

#[binrw]
#[br(import(archive_size: u32, data_start_pos: u64))]
#[derive(Debug)]
pub struct SharcEntry {
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

    pub iv: [u8; 8],
}

impl SharcArchive {
    /// Create a lazy reader for an entry that decompresses on-demand.
    /// 
    /// The reader holds references to the archive and entry, and will decompress
    /// the file data when read() is called.
    pub fn entry_data<'a>(
        &'a self,
        reader: &mut (impl Read + Seek),
        entry: &'a SharcEntry,
    ) -> std::io::Result<Vec<u8>> {
        let data_start_pos = 52 + (self.entries.len() as u64 * 24);
        let (offset, comp_type) = entry.location;
        let entry_offset = data_start_pos + offset as u64;
        
        // Seek to entry and read compressed data
        reader.seek(SeekFrom::Start(entry_offset))?;
        let mut compressed = vec![0u8; entry.compressed_size as usize];
        reader.read_exact(&mut compressed)?;

        let key = self.archive_data.key;
        let iv = entry.iv;

        // Decompress based on type
        let decompressed = match comp_type {
            CompressionType::None => compressed,
            
            CompressionType::ZLib => {
                let decoder = ZlibDecoder::new(&compressed[..]);
                let mut decompressed = Vec::new();
                BufReader::new(decoder).read_to_end(&mut decompressed)?;
                decompressed
            }
            
            CompressionType::EdgeZLib => {
                let mut decoder = SegmentedZlibReader::new(&compressed[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            
            CompressionType::Encrypted => {
                let cipher = XteaPS3::new(&key.into(), &iv.into());
                let decrypted = CryptoReader::new(&compressed[..], cipher);
                let mut decoder = SegmentedZlibReader::new(BufReader::new(decrypted));
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
        };
        
        Ok(decompressed)
    }
}
