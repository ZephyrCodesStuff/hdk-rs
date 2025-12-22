use binrw::prelude::*;

use std::convert::TryInto;

// 1. The Raw Entry (as it appears in the decrypted ToC)
#[derive(BinRead, Debug, Clone)]
pub struct SharcEntry {
    pub name_hash: u32,

    // We map the u32 directly into a tuple: (offset, compression_enum)
    // 0xFFFFFFFC mask clears the last 2 bits
    // 0x3 mask keeps the last 2 bits
    #[br(map = |x: u32| (x & 0xFFFFFFFC, (x & 0x3) as u8))]
    pub offset_and_comp: (u32, u8),

    pub uncompressed_size: u32,
    pub compressed_size: u32,

    #[br(count = 8)]
    pub iv: Vec<u8>,
}

impl SharcEntry {
    // Helper accessors
    pub fn offset(&self) -> u64 {
        self.offset_and_comp.0 as u64
    }
    pub fn compression(&self) -> u8 {
        self.offset_and_comp.1
    }

    pub fn iv_bytes(&self) -> Option<[u8; 8]> {
        self.iv.as_slice().try_into().ok()
    }
}

/// A small, copyable metadata view for a SHARC entry.
///
/// This is intentionally independent from the BinRead struct so callers can
/// inspect metadata without caring about binrw-specific representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharcEntryMetadata {
    pub name_hash: u32,
    pub offset: u64,
    pub compression_raw: u8,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub iv: [u8; 8],
}

impl TryFrom<&SharcEntry> for SharcEntryMetadata {
    type Error = ();

    fn try_from(value: &SharcEntry) -> Result<Self, Self::Error> {
        let iv: [u8; 8] = value.iv.as_slice().try_into().map_err(|_| ())?;
        Ok(Self {
            name_hash: value.name_hash,
            offset: value.offset(),
            compression_raw: value.compression(),
            uncompressed_size: value.uncompressed_size,
            compressed_size: value.compressed_size,
            iv,
        })
    }
}

// 2. The Unencrypted Preamble (File Start)
#[derive(BinRead, Debug, Clone)]
pub struct SharcPreamble {
    // We don't verify magic here because we use it to detect endianness before calling this
    pub magic: u32,

    // Splits the u32 into (Version: u16, Flags: u16)
    #[br(map = |x: u32| ((x >> 16) as u16, (x & 0xFFFF) as u16))]
    pub version_and_flags: (u16, u16),

    #[br(count = 16)]
    pub iv: Vec<u8>,
}

// 3. The Encrypted Inner Header (Decrypted Block)
#[derive(BinRead, Debug, Clone)]
pub struct SharcInnerHeader {
    pub priority: i32,
    pub timestamp: i32,
    pub file_count: u32,

    #[br(count = 16)]
    pub files_key: Vec<u8>,
}

// 4. The Public Header (What your API users see)
// This is NOT a BinRead struct; it is assembled manually.
#[derive(Debug, Clone)]
pub struct SharcHeader {
    pub version: u16,
    pub flags: u16,
    pub iv: [u8; 16],
    pub priority: i32,
    pub timestamp: i32,
    pub file_count: u32,
    pub files_key: [u8; 16],
}
