//! SCE-protected file parsing and decryption helpers
//!
//! This module provides a focused, minimal implementation of the header/metadata
//! parsing and decryption flow we need to extract protected sections from SCE
//! containers.
//!
//! NOTE: keys are not included. Caller is responsible for providing decryption keys.

pub mod crypto;
pub mod errors;
pub mod reader;
pub mod structs;
pub mod writer;

pub use errors::*;
pub use reader::SceArchive;
pub use structs::*;
pub use writer::SceWriter;
