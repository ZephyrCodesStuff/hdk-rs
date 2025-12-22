use std::io::{self, Read, Seek, SeekFrom, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

pub(super) const SEGMENT_HEADER_SIZE: usize = 8;

const MAX_UNCOMPRESSED_SIZE: u32 = u16::MAX as u32 + 1;

#[derive(Debug, Clone, Copy)]
pub(super) struct SegmentEntry {
    pub compressed_size: u16,
    pub uncompressed_size: u32,
    pub file_offset: u64,
}