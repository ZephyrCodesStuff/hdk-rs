//! SDAT (System Data) file handling module
//!
//! This module provides functionality for unpacking and repacking `PlayStation` SDAT files.
//! It is a Rust port of the SDAT-specific functionality from the `make_npdata` C library.

pub mod compression;
pub mod crypto;
pub mod error;
pub mod headers;
pub mod memory;
pub mod reader;
pub mod writer;

// Re-export main types for convenience
pub use crypto::{CryptoContext, SdatKeys};
pub use error::{CompressionError, CryptoError, MemoryError, SdatError};
pub use headers::{EdatHeader, NpdHeader};
pub use memory::MemoryBuffer;
pub use reader::SdatReader;
pub use writer::SdatStreamWriter;
pub use writer::SdatWriter;

#[cfg(test)]
mod tests;

// Extracted DataBlockProcessor to its own module
pub mod block;
pub mod options;
pub use block::DataBlockProcessor;
