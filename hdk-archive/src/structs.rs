use binrw::{BinRead, Endian};
use enumflags2::{BitFlags, bitflags};
use num_enum::{IntoPrimitive, TryFromPrimitive};

pub const ARCHIVE_MAGIC: u32 = 0xADEF17E1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

impl From<Endianness> for Endian {
    fn from(endianness: Endianness) -> Self {
        match endianness {
            Endianness::Little => Self::Little,
            Endianness::Big => Self::Big,
        }
    }
}

impl From<Endian> for Endianness {
    fn from(endian: Endian) -> Self {
        match endian {
            Endian::Little => Self::Little,
            Endian::Big => Self::Big,
        }
    }
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

#[bitflags]
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ArchiveFlagsValue {
    ZTOC = 0b0001,
    LeanZLib = 0b0010,
    Protected = 0b1000,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveFlags(BitFlags<ArchiveFlagsValue>);
impl From<u16> for ArchiveFlags {
    fn from(flags: u16) -> Self {
        Self(BitFlags::from_bits_truncate(flags))
    }
}

impl BinRead for ArchiveFlags {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw = u16::read_options(reader, endian, ())?;
        Ok(raw.into())
    }
}
