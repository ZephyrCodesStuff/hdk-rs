use wasm_bindgen::prelude::*;

use std::io::Cursor;

use js_sys::{Array as JsArray, Uint8Array};
use serde_wasm_bindgen as swb;

use crate::sdat::structs::{Sdat, header_from_raw};
use crate::sdat::to_arr16;

use hdk_sdat::crypto::SdatKeys;
use hdk_sdat::reader::SdatReader as InnerSdatReader;

#[wasm_bindgen]
impl Sdat {
    /// Create an SDAT reader from raw bytes and a concatenated key buffer.
    ///
    /// The `keys` slice must be 112 bytes (7 keys * 16 bytes each) in the
    /// following order: sdat_key, edat_key_0, edat_key_1, edat_hash_0,
    /// edat_hash_1, npdrm_omac_key_2, npdrm_omac_key_3.
    #[wasm_bindgen(constructor)]
    pub fn new(buf: &[u8], keys: &[u8]) -> Result<Sdat, JsValue> {
        if keys.len() != 16 * 7 {
            return Err(JsValue::from_str("keys must be 112 bytes (7*16)"));
        }

        let sdat_keys = SdatKeys {
            sdat_key: to_arr16(&keys[0..16]),
            edat_key_0: to_arr16(&keys[16..32]),
            edat_key_1: to_arr16(&keys[32..48]),
            edat_hash_0: to_arr16(&keys[48..64]),
            edat_hash_1: to_arr16(&keys[64..80]),
            npdrm_omac_key_2: to_arr16(&keys[80..96]),
            npdrm_omac_key_3: to_arr16(&keys[96..112]),
        };

        let cursor = Cursor::new(buf.to_vec());

        let reader = InnerSdatReader::open(cursor, &sdat_keys)
            .map_err(|e| JsValue::from_str(&format!("Failed to open SDAT: {}", e)))?;

        Ok(Sdat {
            inner: Some(reader),
        })
    }

    /// Return headers as a JS object { npd: ..., edat: ... }
    pub fn header(&self) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let npd = r.npd_header();
        let edat = r.edat_header();

        let (npd_js, edat_js) = header_from_raw(npd, edat);

        // Convert into object with keys
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("npd"),
            &swb::to_value(&npd_js)
                .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?,
        )
        .unwrap();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("edat"),
            &swb::to_value(&edat_js)
                .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?,
        )
        .unwrap();

        Ok(JsValue::from(obj))
    }

    pub fn file_size(&self) -> Result<u64, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        Ok(r.file_size())
    }

    pub fn block_size(&self) -> Result<u32, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        Ok(r.block_size())
    }

    pub fn block_count(&self) -> Result<usize, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        Ok(r.block_count())
    }

    /// Decrypt the full payload into memory and return bytes.
    pub fn decrypt_to_vec(&mut self) -> Result<Vec<u8>, JsValue> {
        let r = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        r.decrypt_to_vec()
            .map_err(|e| JsValue::from_str(&format!("Decrypt failed: {}", e)))
    }

    /// Decrypt into chunked Uint8Array pieces of `chunk_size`.
    pub fn decrypt_to_chunks(&mut self, chunk_size: usize) -> Result<JsValue, JsValue> {
        if chunk_size == 0 {
            return Err(JsValue::from_str("chunk_size must be > 0"));
        }

        let data = self.decrypt_to_vec()?;
        let js_arr = JsArray::new();

        let mut off = 0usize;
        while off < data.len() {
            let end = std::cmp::min(off + chunk_size, data.len());
            let slice = &data[off..end];
            let chunk = Uint8Array::new_with_length(slice.len() as u32);
            chunk.copy_from(slice);
            js_arr.push(&chunk);
            off = end;
        }

        Ok(JsValue::from(js_arr))
    }

    pub fn close(&mut self) {
        self.inner = None;
    }
}
