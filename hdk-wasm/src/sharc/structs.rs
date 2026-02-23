use std::io::Cursor;

use wasm_bindgen::prelude::*;

use hdk_archive::sharc::structs::SharcArchive;

use serde::Serialize;

#[wasm_bindgen]
pub struct Sharc {
    #[wasm_bindgen(skip)]
    pub(crate) inner: Option<SharcArchive>,
    #[wasm_bindgen(skip)]
    pub(crate) reader: Cursor<Vec<u8>>,
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
    pub offset: u32,
    pub compression_raw: u8,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub iv: [u8; 8],
}
