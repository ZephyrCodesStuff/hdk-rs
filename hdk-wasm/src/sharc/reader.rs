use wasm_bindgen::prelude::*;

use std::io::{Cursor, Read};

use crate::sharc::structs::{Sharc, header_from_raw, meta_from_raw};
use hdk_archive::archive::ArchiveReader;
use hdk_archive::sharc::reader::SharcReader as InnerSharcReader;

use js_sys::{Array as JsArray, Uint8Array};
use serde_wasm_bindgen as swb;

#[wasm_bindgen]
impl Sharc {
    /// Create a SHARC reader from raw bytes and a 32-byte key.
    #[wasm_bindgen(constructor)]
    pub fn new(buf: &[u8], key: &[u8]) -> Result<Self, JsValue> {
        if key.len() != 32 {
            return Err(JsValue::from_str("Key must be 32 bytes"));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key[..32]);

        let cursor = Cursor::new(buf.to_vec());
        let reader = InnerSharcReader::open(cursor, key_arr)
            .map_err(|e| JsValue::from_str(&format!("Failed to open SHARC: {}", e)))?;

        Ok(Self {
            inner: Some(reader),
        })
    }

    /// Return the parsed header as a JS value (serializable object)
    pub fn header(&self) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let raw = r.header();
        let js = swb::to_value(&header_from_raw(raw))
            .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?;
        Ok(js)
    }

    /// Number of entries in the archive
    pub fn entry_count(&self) -> Result<usize, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        Ok(r.entry_count())
    }

    /// Get metadata for a single entry
    pub fn entry_metadata(&self, index: usize) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let meta = r
            .entry_metadata(index)
            .map_err(|e| JsValue::from_str(&format!("Failed to get metadata: {}", e)))?;

        let js = swb::to_value(&meta_from_raw(meta))
            .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?;
        Ok(js)
    }

    /// Return the entire TOC as a JS array of metadata objects.
    pub fn list_toc(&self) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let count = r.entry_count();
        let mut arr = Vec::with_capacity(count);

        for i in 0..count {
            let meta = r
                .entry_metadata(i)
                .map_err(|e| JsValue::from_str(&format!("Failed to get metadata: {}", e)))?;
            arr.push(meta_from_raw(meta));
        }

        let js = swb::to_value(&arr)
            .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?;
        Ok(js)
    }

    /// Read an entry and return an array of `Uint8Array` chunks of `chunk_size`.
    pub fn read_entry_chunks(
        &mut self,
        index: usize,
        chunk_size: usize,
    ) -> Result<JsValue, JsValue> {
        if chunk_size == 0 {
            return Err(JsValue::from_str("chunk_size must be > 0"));
        }

        let r = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let mut reader_box = r
            .entry_reader(index)
            .map_err(|e| JsValue::from_str(&format!("Failed to open entry reader: {}", e)))?;

        let js_arr = JsArray::new();
        let mut buf = vec![0u8; chunk_size];

        loop {
            match reader_box.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = Uint8Array::new_with_length(n as u32);
                    chunk.copy_from(&buf[..n]);
                    js_arr.push(&chunk);
                }
                Err(e) => return Err(JsValue::from_str(&format!("read failed: {}", e))),
            }
        }

        Ok(JsValue::from(js_arr))
    }

    /// Read an entry fully into memory and return the bytes.
    pub fn read_entry(&mut self, index: usize) -> Result<Vec<u8>, JsValue> {
        let r = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let mut reader_box = r
            .entry_reader(index)
            .map_err(|e| JsValue::from_str(&format!("Failed to open entry reader: {}", e)))?;

        let mut out = Vec::new();
        reader_box
            .read_to_end(&mut out)
            .map_err(|e| JsValue::from_str(&format!("Failed to read entry: {}", e)))?;

        Ok(out)
    }

    /// Consume the reader and free resources.
    pub fn close(&mut self) {
        self.inner = None;
    }
}
