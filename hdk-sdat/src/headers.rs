//! SDAT header structures and parsing

use crate::error::{MemoryError, SdatError};

/// NPD (PlayStation Data) header structure
#[repr(C)]
#[derive(Debug, Clone)]
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

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buffer[0..4]);

        let version = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let license = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
        let type_ = u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);

        let mut content_id = [0u8; 0x30];
        content_id.copy_from_slice(&buffer[16..16 + 0x30]);

        let mut digest = [0u8; 0x10];
        digest.copy_from_slice(&buffer[64..64 + 0x10]);

        let mut title_hash = [0u8; 0x10];
        title_hash.copy_from_slice(&buffer[80..80 + 0x10]);

        let mut dev_hash = [0u8; 0x10];
        dev_hash.copy_from_slice(&buffer[96..96 + 0x10]);

        let unk1 = u64::from_be_bytes([
            buffer[112],
            buffer[113],
            buffer[114],
            buffer[115],
            buffer[116],
            buffer[117],
            buffer[118],
            buffer[119],
        ]);

        let unk2 = u64::from_be_bytes([
            buffer[120],
            buffer[121],
            buffer[122],
            buffer[123],
            buffer[124],
            buffer[125],
            buffer[126],
            buffer[127],
        ]);

        Ok(NpdHeader {
            magic,
            version,
            license,
            type_,
            content_id,
            digest,
            title_hash,
            dev_hash,
            unk1,
            unk2,
        })
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
    pub fn region_from_locale() -> String {
        std::env::var("LANG")
            .ok()
            .and_then(|l| l.get(0..2).map(|s| s.to_uppercase()))
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
    /// Returns a new NpdHeader configured for SDAT files
    pub fn new_sdat(content_id: [u8; 0x30], dev_hash: [u8; 16], title_hash: [u8; 16]) -> Self {
        // Generate a random digest (C implementation uses prng)
        // For now, we'll use a fixed random-like pattern to avoid adding rand dependency if not needed
        // In a real implementation, this should be cryptographically secure random
        let mut digest = [0u8; 16];
        for i in 0..16 {
            digest[i] = (i as u8).wrapping_mul(17).wrapping_add(0x42);
        }

        NpdHeader {
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

        buffer[0..4].copy_from_slice(&self.magic);
        buffer[4..8].copy_from_slice(&self.version.to_be_bytes());
        buffer[8..12].copy_from_slice(&self.license.to_be_bytes());
        buffer[12..16].copy_from_slice(&self.type_.to_be_bytes());
        buffer[16..16 + 0x30].copy_from_slice(&self.content_id);
        buffer[64..64 + 0x10].copy_from_slice(&self.digest);
        buffer[80..80 + 0x10].copy_from_slice(&self.title_hash);
        buffer[96..96 + 0x10].copy_from_slice(&self.dev_hash);
        buffer[112..120].copy_from_slice(&self.unk1.to_be_bytes());
        buffer[120..128].copy_from_slice(&self.unk2.to_be_bytes());

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

        Ok(EdatHeader {
            flags,
            block_size,
            file_size,
        })
    }

    /// Check if this is an SDAT file based on flags
    pub fn is_sdat(&self) -> bool {
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
    /// Returns a new EdatHeader configured for SDAT files
    pub fn new_sdat(file_size: u64, block_size: u32, compressed: bool) -> Self {
        let mut flags = Self::SDAT_FLAG;

        if compressed {
            flags |= crate::crypto::EDAT_COMPRESSED_FLAG;
        }

        EdatHeader {
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
