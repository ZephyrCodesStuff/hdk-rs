use wasm_bindgen::prelude::*;

use std::io::Cursor;

use hdk_archive::bar::reader::BarReader as InnerBarReader;
use hdk_archive::bar::structs::{BarEntryMetadata as RawEntryMeta, BarHeader as RawHeader};

use serde::Serialize;

#[wasm_bindgen]
pub struct Bar {
    #[wasm_bindgen(skip)]
    pub(crate) inner: Option<InnerBarReader<Cursor<Vec<u8>>>>,
}

#[derive(Serialize)]
pub struct BarHeader {
    pub version: u16,
    pub flags: u16,
    pub priority: i32,
    pub timestamp: i32,
    pub file_count: u32,
}

#[derive(Serialize)]
pub struct BarEntryMetadata {
    pub name_hash: String,
    pub offset: u32,
    pub compression_raw: u8,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
}

pub(crate) fn header_from_raw(h: RawHeader) -> BarHeader {
    BarHeader {
        version: h.version_and_flags.0,
        flags: h.version_and_flags.1,
        priority: h.priority,
        timestamp: h.timestamp,
        file_count: h.file_count,
    }
}

pub(crate) fn meta_from_raw(m: RawEntryMeta) -> BarEntryMetadata {
    BarEntryMetadata {
        name_hash: format!("{:08X}", m.name_hash.0),
        offset: m.offset,
        compression_raw: m.compression.into(),
        uncompressed_size: m.uncompressed_size,
        compressed_size: m.compressed_size,
    }
}
