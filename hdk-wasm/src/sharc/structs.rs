use wasm_bindgen::prelude::*;

use std::io::Cursor;

use hdk_archive::sharc::reader::SharcReader as InnerSharcReader;
use hdk_archive::sharc::structs::{SharcEntryMetadata as RawEntryMeta, SharcHeader as RawHeader};

use serde::Serialize;

#[wasm_bindgen]
pub struct Sharc {
    #[wasm_bindgen(skip)]
    pub(crate) inner: Option<InnerSharcReader<Cursor<Vec<u8>>>>,
}

#[derive(Serialize)]
pub struct SharcHeader {
    pub version: u16,
    pub flags: u16,
    pub iv: [u8; 16],
    pub priority: i32,
    pub timestamp: i32,
    pub file_count: u32,
    pub files_key: [u8; 16],
}

#[derive(Serialize)]
pub struct SharcEntryMetadata {
    pub name_hash: String,
    pub offset: u64,
    pub compression_raw: u8,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub iv: [u8; 8],
}

pub(crate) fn header_from_raw(h: RawHeader) -> SharcHeader {
    SharcHeader {
        version: h.version,
        flags: h.flags.bits(),
        iv: h.iv,
        priority: h.priority,
        timestamp: h.timestamp,
        file_count: h.file_count,
        files_key: h.files_key,
    }
}

pub(crate) fn meta_from_raw(m: RawEntryMeta) -> SharcEntryMetadata {
    SharcEntryMetadata {
        name_hash: format!("{:08X}", m.name_hash.0),
        offset: m.offset,
        compression_raw: m.compression_raw,
        uncompressed_size: m.uncompressed_size,
        compressed_size: m.compressed_size,
        iv: m.iv,
    }
}
