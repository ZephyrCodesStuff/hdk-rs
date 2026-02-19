//! Options structs for block processing operations.
//!
//! This module provides builder-pattern options for the various
//! block processing functions in the SDAT handling library.
//!
//! Options contain configuration and context (headers, keys, indices),
//! while the primary data buffers are passed as separate arguments.

use derive_builder::Builder;

use crate::block::BlockMetadata;
use crate::headers::{EdatHeader, NpdHeader};

/// Options for parsing block metadata.
///
/// Contains the configuration needed for parsing; the metadata buffer
/// itself is passed separately to `parse_block_metadata`.
#[derive(Debug, Clone, Builder)]
#[builder(setter(into))]
pub struct ParseBlockMetadataOptions {
    /// Index of the block to parse
    pub block_index: usize,
    /// EDAT header information
    pub edat_header: EdatHeader,
    /// NPD header information
    pub npd_header: NpdHeader,
    /// Offset to the metadata section in the file
    pub metadata_offset: u64,
    /// Total number of blocks
    pub block_num: usize,
}

/// Options for decrypting a data block.
///
/// Contains the configuration needed for decryption; the encrypted data
/// itself is passed separately to `decrypt_data_block`.
#[derive(Debug, Clone, Builder)]
#[builder(setter(into))]
pub struct DecryptBlockOptions {
    /// Metadata for this block (contains hash, offset, length)
    pub block_metadata: BlockMetadata,
    /// Index of the block being decrypted
    pub block_index: u32,
    /// EDAT header information
    pub edat_header: EdatHeader,
    /// NPD header information
    pub npd_header: NpdHeader,
    /// Cryptographic key for decryption
    pub crypt_key: [u8; 16],
}

/// Options for encrypting a data block.
///
/// Contains the configuration needed for encryption; the plaintext data
/// itself is passed separately to `encrypt_data_block`.
#[derive(Debug, Clone, Builder)]
#[builder(setter(into))]
pub struct EncryptBlockOptions {
    /// Index of the block being encrypted
    pub block_index: u32,
    /// EDAT header information
    pub edat_header: EdatHeader,
    /// NPD header information
    pub npd_header: NpdHeader,
    /// Cryptographic key for encryption
    pub crypt_key: [u8; 16],
}

/// Options for low-level crypto operations (used by internal helpers)
#[derive(Debug, Clone, Builder)]
#[builder(setter(into))]
pub struct CryptoOpOptions {
    /// Hash mode flags
    pub hash_mode: u32,
    /// Crypto mode flags
    pub crypto_mode: u32,
    /// Version value used for key/hash selection
    pub version: u32,
    /// Key material (pre-key-result)
    pub key: [u8; 16],
    /// IV material
    pub iv: [u8; 16],
    /// Hash key material
    pub hash_key: [u8; 16],
    /// Expected hash (from metadata)
    pub expected_hash: Vec<u8>,
}
