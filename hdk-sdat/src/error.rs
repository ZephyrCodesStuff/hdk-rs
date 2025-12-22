//! Error types for SDAT operations

use thiserror::Error;

/// Main error type for SDAT operations
#[derive(Debug, Error)]
pub enum SdatError {
    #[error("Invalid SDAT header: {0}")]
    InvalidHeader(String),
    #[error("Invalid hash: {0}")]
    InvalidHash(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Compression operation failed: {0}")]
    CompressionError(#[from] CompressionError),
    #[error("Buffer operation failed: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("Invalid file format")]
    InvalidFormat,
    #[error("Buffer too small: needed {needed}, got {available}")]
    BufferTooSmall { needed: usize, available: usize },
}

/// Cryptographic operation errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES operation failed: {0}")]
    AesError(String),
    #[error("Hash verification failed")]
    HashMismatch,
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Invalid IV length: expected {expected}, got {actual}")]
    InvalidIvLength { expected: usize, actual: usize },
}

/// Compression operation errors
#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("Compression failed: {0}")]
    CompressionFailed(String),
    #[error("Invalid compressed data format")]
    InvalidFormat,
}

/// Memory buffer operation errors
#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Buffer overflow: attempted to access {position} in buffer of size {size}")]
    BufferOverflow { position: usize, size: usize },
    #[error("Buffer underflow: attempted to read {requested} bytes, only {available} available")]
    BufferUnderflow { requested: usize, available: usize },
    #[error("Invalid seek position: {position}")]
    InvalidSeekPosition { position: usize },
    #[error("Memory allocation failed")]
    AllocationFailed,
}
