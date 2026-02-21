use wasm_bindgen::prelude::*;

use std::io::Cursor;

use serde::Serialize;

use hdk_sdat::headers::{EdatHeader, NpdHeader};

/// WASM-visible SDAT wrapper container.
#[wasm_bindgen]
pub struct Sdat {
    #[wasm_bindgen(skip)]
    pub(crate) inner: Option<hdk_sdat::reader::SdatReader<Cursor<Vec<u8>>>>,
}

#[derive(Serialize)]
pub struct NpdHeaderJs {
    magic: Vec<u8>,
    version: u32,
    license: u32,
    type_: u32,
    content_id: Vec<u8>,
    digest: Vec<u8>,
    title_hash: Vec<u8>,
    dev_hash: Vec<u8>,
    unk1: u64,
    unk2: u64,
}

#[derive(Serialize)]
pub struct EdatHeaderJs {
    flags: u32,
    block_size: u32,
    file_size: u64,
}

pub(crate) fn header_from_raw(npd: &NpdHeader, edat: &EdatHeader) -> (NpdHeaderJs, EdatHeaderJs) {
    let npd_js = NpdHeaderJs {
        magic: npd.magic.to_vec(),
        version: npd.version,
        license: npd.license,
        type_: npd.type_,
        content_id: npd.content_id.to_vec(),
        digest: npd.digest.to_vec(),
        title_hash: npd.title_hash.to_vec(),
        dev_hash: npd.dev_hash.to_vec(),
        unk1: npd.unk1,
        unk2: npd.unk2,
    };

    let edat_js = EdatHeaderJs {
        flags: edat.flags,
        block_size: edat.block_size,
        file_size: edat.file_size,
    };

    (npd_js, edat_js)
}
