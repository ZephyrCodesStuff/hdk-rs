//! PS3 PKG file format reader.
//!
//! Supports both debug (SHA-1 stream cipher) and retail (AES-128-CTR) PKGs.

pub mod reader;
pub mod structs;

pub use reader::{Items, PkgArchive, PkgError, PkgItemReader};
pub use structs::{
    PKG_MAGIC, PS3_AES_KEY, PSP_AES_KEY, PkgContentType, PkgDrmType, PkgExtendedHeader,
    PkgFileEntry, PkgHeader, PkgItem, PkgPlatform, PkgReleaseType,
};
