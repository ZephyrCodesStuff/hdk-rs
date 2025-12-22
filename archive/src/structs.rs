use binrw::BinRead;
use num_enum::{IntoPrimitive, TryFromPrimitive};

pub const ARCHIVE_MAGIC: u32 = 0xADEF17E1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BinRead, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
#[br(repr = u8)]
pub enum CompressionType {
    None,
    ZLib,
    EdgeZLib,
    Encrypted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum ArchiveVersion {
    BAR = 256,
    SHARC = 512,
    Unknown = 0xFFFF,
}

use enumflags2::bitflags;

#[bitflags]
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ArchiveFlags {
    ZTOC = 0b0001,
    LeanZLib = 0b0010,
    Protected = 0b1000,
}
