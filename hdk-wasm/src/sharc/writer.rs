use js_sys::Uint8Array;
use std::io::Cursor;
use wasm_bindgen::prelude::*;

use hdk_archive::sharc::writer::SharcWriter as InnerSharcWriter;
use hdk_archive::structs::{CompressionType, Endianness};
use hdk_secure::hash::AfsHash;

#[wasm_bindgen]
pub struct SharcWriter {
    inner: Option<InnerSharcWriter<Cursor<Vec<u8>>>>,
}

#[wasm_bindgen]
impl SharcWriter {
    /// Create a new in-memory SHARC writer. `key` must be 32 bytes. `big_endian` selects endianness.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8], big_endian: bool) -> Result<SharcWriter, JsValue> {
        if key.len() != 32 {
            return Err(JsValue::from_str("Key must be 32 bytes"));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key[..32]);

        let endian = if big_endian {
            Endianness::Big
        } else {
            Endianness::Little
        };

        let cursor = Cursor::new(Vec::new());
        let writer = InnerSharcWriter::new(cursor, key_arr, endian)
            .map_err(|e| JsValue::from_str(&format!("Failed to create writer: {}", e)))?;

        Ok(SharcWriter {
            inner: Some(writer),
        })
    }

    /// Add an entry from bytes. `name_hash` is the AFS hash as u32, `compression_raw` is the u8 enum value.
    pub fn add_entry_from_bytes(
        &mut self,
        name_hash: u32,
        compression_raw: u8,
        data: &[u8],
    ) -> Result<(), JsValue> {
        let w = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Writer closed"))?;

        let comp = CompressionType::try_from(compression_raw)
            .map_err(|_| JsValue::from_str("Invalid compression type"))?;
        let ah = AfsHash(name_hash as i32);

        w.add_entry_from_bytes(ah, comp, data)
            .map_err(|e| JsValue::from_str(&format!("add entry failed: {}", e)))
    }

    /// Finalize and return the archive bytes as a `Uint8Array`.
    pub fn finish(mut self) -> Result<Uint8Array, JsValue> {
        let writer = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("Writer closed"))?;

        let out_cursor = writer
            .finish()
            .map_err(|e| JsValue::from_str(&format!("finish failed: {}", e)))?;
        let vec = out_cursor.into_inner();

        let arr = Uint8Array::new_with_length(vec.len() as u32);
        arr.copy_from(&vec[..]);
        Ok(arr)
    }

    /// Close without finishing (drop writer)
    pub fn close(&mut self) {
        self.inner = None;
    }
}
