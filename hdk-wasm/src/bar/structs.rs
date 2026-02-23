use std::io::Cursor;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use hdk_archive::bar::structs::{BarArchive as RawArchive, BarEntry as RawEntryMeta};

#[wasm_bindgen]
pub struct Bar {
    #[wasm_bindgen(skip)]
    pub(crate) inner: Option<RawArchive>,
    #[wasm_bindgen(skip)]
    pub(crate) reader: Cursor<Vec<u8>>,
    #[wasm_bindgen(skip)]
    pub(crate) default_key: [u8; 32],
    #[wasm_bindgen(skip)]
    pub(crate) signature_key: [u8; 32],
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

pub(crate) const fn header_from_raw(h: &RawArchive) -> BarHeader {
    BarHeader {
        version: h.archive_info.version,
        flags: h.archive_info.flags,
        priority: h.archive_data.priority,
        timestamp: h.archive_data.timestamp,
        file_count: h.archive_data.file_count,
    }
}

pub(crate) fn meta_from_raw(m: &RawEntryMeta) -> BarEntryMetadata {
    BarEntryMetadata {
        name_hash: format!("{:08X}", m.name_hash.0),
        offset: m.location.0,
        compression_raw: m.location.1 as u8,
        uncompressed_size: m.uncompressed_size,
        compressed_size: m.compressed_size,
    }
}
