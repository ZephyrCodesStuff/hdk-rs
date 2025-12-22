use binrw::BinRead;
use num_enum::{IntoPrimitive, TryFromPrimitive};

pub const ARCHIVE_MAGIC: u32 = 0xADEF17E1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, BinRead, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
#[br(repr = u8)]
pub enum CompressionType {
    None,
    ZLib,
    EdgeZLib,
    Encrypted,
}
