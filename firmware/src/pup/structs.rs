use core::fmt;

/// PUP Magic: "Sony Computer Entertainment Update File"
///
/// On-disk it appears as the bytes: `SCEUF\0\0\0`.
pub const PUP_MAGIC: &[u8; 8] = b"SCEUF\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PupMagic(pub [u8; 8]);

impl PupMagic {
    pub fn is_valid(&self) -> bool {
        &self.0 == PUP_MAGIC
    }
}

/// Common PUP entry IDs.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PupEntries {
    FirmwareVersion = 0x100,
    UpdateFilesTar = 0x300,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PupHeader {
    pub magic: PupMagic,
    pub package_version: u64,
    pub image_version: u64,
    pub file_count: u64,
    pub header_length: u64,
    pub data_length: u64,
}

impl fmt::Display for PupHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PupHeader(magic={:?}, package_version={}, image_version={}, file_count={}, header_length={}, data_length={})",
            self.magic.0,
            self.package_version,
            self.image_version,
            self.file_count,
            self.header_length,
            self.data_length
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PupFileInfo {
    pub entry_id: u64,
    pub data_offset: u64,
    pub data_len: u64,
    pub padding: [u8; 8],
}

impl fmt::Display for PupFileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PupFileInfo(entry_id={:#x}, data_offset={}, data_len={})",
            self.entry_id, self.data_offset, self.data_len
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PupHash {
    pub entry_id: u64,
    pub hash: [u8; 20],
    pub padding: [u8; 4],
}

impl fmt::Display for PupHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PupHash(entry_id={:#x}, hash={:02x?})",
            self.entry_id, self.hash
        )
    }
}

/// Copyable metadata view of an entry (file table row + optional hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PupEntryMetadata {
    pub entry_id: u64,
    pub data_offset: u64,
    pub data_len: u64,
    pub hash: Option<[u8; 20]>,
}
