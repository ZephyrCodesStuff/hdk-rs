use crate::structs::CompressionType;
use binrw::prelude::*;
use hdk_secure::hash::AfsHash;

#[derive(BinRead, Debug, Clone)]
pub struct BarHeader {
    #[br(map = |x: u32| ((x >> 16) as u16, (x & 0xFFFF) as u16))]
    pub version_and_flags: (u16, u16),

    pub priority: i32,
    pub timestamp: i32,
    pub file_count: u32,
}

#[derive(BinRead, Debug, Clone)]
pub struct BarEntry {
    pub name_hash: i32,
    #[br(map = |x: u32| (x & 0xFFFFFFFC, (x & 0x3) as u8))]
    pub offset_and_comp: (u32, u8),

    pub uncompressed_size: u32,
    pub compressed_size: u32,
}

impl BarEntry {
    pub const fn name_hash(&self) -> AfsHash {
        AfsHash(self.name_hash)
    }

    pub const fn offset(&self) -> u32 {
        self.offset_and_comp.0
    }

    pub fn compression(&self) -> CompressionType {
        let raw = self.offset_and_comp.1;
        CompressionType::try_from(raw).unwrap_or(CompressionType::None)
    }
}

/// Metadata view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarEntryMetadata {
    pub name_hash: AfsHash,
    pub offset: u32,
    pub compression: CompressionType,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
}

impl From<&BarEntry> for BarEntryMetadata {
    fn from(entry: &BarEntry) -> Self {
        Self {
            name_hash: AfsHash(entry.name_hash),
            offset: entry.offset(),
            compression: entry.compression(),
            uncompressed_size: entry.uncompressed_size,
            compressed_size: entry.compressed_size,
        }
    }
}
