//! SDAT header structures and parsing

use crate::error::{MemoryError, SdatError};
use binrw::{BinRead, BinWrite};
use enumflags2::{BitFlags, bitflags};

/// NPD (`PlayStation` Data) header structure
#[repr(C)]
#[derive(Debug, Clone, BinRead, BinWrite)]
#[br(big)]
#[bw(big)]
pub struct NpdHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub license: u32,
    pub type_: u32,
    pub content_id: [u8; 0x30],
    pub digest: [u8; 0x10],
    pub title_hash: [u8; 0x10],
    pub dev_hash: [u8; 0x10],
    pub unk1: u64,
    pub unk2: u64,
}

/// EDAT header structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EdatHeader {
    pub flags: u32,
    pub block_size: u32,
    pub file_size: u64,
}

/// EDAT flag enum for typed BitFlags
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[bitflags]
#[repr(u32)]
pub enum EdatFlag {
    Compressed = 0b0000_0001,
    Flag0x02 = 0b0000_0010,
    EncryptedKey = 0b0000_1000,
    Flag0x10 = 0b0001_0000,
    Flag0x20 = 0b0010_0000,
    DebugData = 0b1000_0000_0000_0000_0000_0000_0000_0000,
}

impl EdatHeader {
    /// Return flags as typed BitFlags
    #[must_use]
    pub fn flags_bits(&self) -> BitFlags<EdatFlag> {
        // from_bits_truncate will ignore unknown bits
        BitFlags::from_bits_truncate(self.flags)
    }

    /// Set flags from BitFlags
    pub fn set_flags_from_bits(&mut self, bits: BitFlags<EdatFlag>) {
        self.flags = bits.bits();
    }
}

impl NpdHeader {
    /// Size of NPD header in bytes
    pub const SIZE: usize = 0x80;

    /// Expected magic number for NPD files
    pub const MAGIC: [u8; 4] = *b"NPD\0";

    /// Parse NPD header from byte buffer
    pub fn parse(buffer: &[u8]) -> Result<Self, SdatError> {
        if buffer.len() < Self::SIZE {
            return Err(SdatError::MemoryError(MemoryError::BufferUnderflow {
                requested: Self::SIZE,
                available: buffer.len(),
            }));
        }
        // Use `binrw` to parse the header from the provided buffer (big-endian per struct attrs)
        let mut cursor = std::io::Cursor::new(buffer);
        Self::read(&mut cursor)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to read NPD header: {}", e)))
    }

    /// Validate NPD header structure and magic numbers
    pub fn validate(&self) -> Result<(), SdatError> {
        if self.magic != Self::MAGIC {
            return Err(SdatError::InvalidHeader(format!(
                "Invalid magic number: expected {:?}, got {:?}",
                Self::MAGIC,
                self.magic
            )));
        }

        // TODO: Add additional validation logic
        Ok(())
    }

    /// Create a new Content ID for SDAT files
    ///
    /// # Returns
    ///
    /// Returns a Content ID string suitable for SDAT files in the format "XXYYYY-AAAABBBBB_CC-DDDDDDDDDDDDDDDD"
    #[must_use]
    pub fn generate_content_id() -> String {
        let prefix = "BLAHAJ";

        let (git_hash, region) = {
            // If metadata feature is enabled, use git version and locale region to
            // generate dynamic content ID
            #[cfg(feature = "metadata")]
            {
                let git_hash = git_version::git_version!(args = ["--abbrev=9", "--always"]);
                let region = Self::region_from_locale();
                (git_hash, region)
            }
            // If not, use default placeholders
            #[cfg(not(feature = "metadata"))]
            {
                ("MISSINGNO".to_string(), "XX".to_string())
            }
        };

        let suffix = "NOBUGSPLSTHXMWAH";

        format!("{prefix}-{git_hash}_{region}-{suffix}").to_uppercase()
    }

    /// Get region code from system locale (LANG environment variable)
    #[cfg(feature = "metadata")]
    #[must_use]
    pub fn region_from_locale() -> String {
        std::env::var("LANG")
            .ok()
            .and_then(|l| l.get(0..2).map(str::to_uppercase))
            .unwrap_or_else(|| "XX".to_string())
    }

    /// Create a new NPD header for SDAT files
    ///
    /// # Arguments
    ///
    /// * `content_id` - Content ID (32 bytes)
    /// * `dev_hash` - Device hash (16 bytes)
    /// * `title_hash` - Title hash (16 bytes)
    ///
    /// # Returns
    ///
    /// Returns a new `NpdHeader` configured for SDAT files
    #[must_use]
    pub fn new_sdat(content_id: [u8; 0x30], dev_hash: [u8; 16], title_hash: [u8; 16]) -> Self {
        // Generate a random digest (C implementation uses prng)
        // For now, we'll use a fixed random-like pattern to avoid adding rand dependency if not needed
        // In a real implementation, this should be cryptographically secure random
        let mut digest = [0u8; 16];
        for (i, val) in (0..16).enumerate() {
            digest[i] = (val as u8).wrapping_mul(17).wrapping_add(0x42);
        }

        Self {
            magic: Self::MAGIC,
            version: 4, // Use version 4 for SDAT files
            license: 1, // Standard license type
            type_: 1,   // Standard type
            content_id,
            digest,
            title_hash,
            dev_hash,
            unk1: 0,
            unk2: 0,
        }
    }

    /// Serialize NPD header to bytes
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer to write header to (must be at least SIZE bytes)
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<(), SdatError> {
        if buffer.len() < Self::SIZE {
            return Err(SdatError::MemoryError(MemoryError::BufferUnderflow {
                requested: Self::SIZE,
                available: buffer.len(),
            }));
        }
        let mut cursor = std::io::Cursor::new(buffer);
        self.write(&mut cursor)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to write NPD header: {}", e)))?;

        Ok(())
    }
}

impl EdatHeader {
    /// Size of EDAT header in bytes
    pub const SIZE: usize = 0x10;

    /// SDAT flag value
    pub const SDAT_FLAG: u32 = 0x01000000;

    /// Parse EDAT header from byte buffer
    pub fn parse(buffer: &[u8]) -> Result<Self, SdatError> {
        if buffer.len() < Self::SIZE {
            return Err(SdatError::MemoryError(MemoryError::BufferUnderflow {
                requested: Self::SIZE,
                available: buffer.len(),
            }));
        }

        let flags = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        let block_size = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let file_size = u64::from_be_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14],
            buffer[15],
        ]);

        Ok(Self {
            flags,
            block_size,
            file_size,
        })
    }

    /// Check if this is an SDAT file based on flags
    #[must_use]
    pub const fn is_sdat(&self) -> bool {
        (self.flags & Self::SDAT_FLAG) != 0
    }

    /// Create a new EDAT header for SDAT files
    ///
    /// # Arguments
    ///
    /// * `file_size` - Size of the original data
    /// * `block_size` - Block size for encryption (typically 0x8000)
    /// * `compressed` - Whether the data is compressed
    ///
    /// # Returns
    ///
    /// Returns a new `EdatHeader` configured for SDAT files
    #[must_use]
    pub const fn new_sdat(file_size: u64, block_size: u32, compressed: bool) -> Self {
        let mut flags = Self::SDAT_FLAG;

        if compressed {
            flags |= crate::crypto::EDAT_COMPRESSED_FLAG;
        }

        Self {
            flags,
            block_size,
            file_size,
        }
    }

    /// Serialize EDAT header to bytes
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer to write header to (must be at least SIZE bytes)
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<(), SdatError> {
        if buffer.len() < Self::SIZE {
            return Err(SdatError::MemoryError(MemoryError::BufferUnderflow {
                requested: Self::SIZE,
                available: buffer.len(),
            }));
        }

        buffer[0..4].copy_from_slice(&self.flags.to_be_bytes());
        buffer[4..8].copy_from_slice(&self.block_size.to_be_bytes());
        buffer[8..16].copy_from_slice(&self.file_size.to_be_bytes());

        Ok(())
    }
}
