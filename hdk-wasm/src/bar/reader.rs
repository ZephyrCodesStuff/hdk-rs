use wasm_bindgen::prelude::*;

use std::io::{Cursor, Read};

use crate::bar::structs::{Bar, header_from_raw, meta_from_raw};
use hdk_archive::archive::ArchiveReader;
use hdk_archive::bar::reader::BarReader as InnerBarReader;
use js_sys::{Array as JsArray, Uint8Array};
use serde_wasm_bindgen as swb;

#[wasm_bindgen]
impl Bar {
    #[wasm_bindgen(constructor)]
    pub fn new(
        buf: &[u8],
        default_key: &[u8],
        signature_key: &[u8],
        big_endian: bool,
    ) -> Result<Bar, JsValue> {
        if default_key.len() != 32 || signature_key.len() != 32 {
            return Err(JsValue::from_str("Keys must be 32 bytes"));
        }

        let mut def = [0u8; 32];
        def.copy_from_slice(&default_key[..32]);
        let mut sig = [0u8; 32];
        sig.copy_from_slice(&signature_key[..32]);

        let cursor = Cursor::new(buf.to_vec());

        let endian = if big_endian {
            Some(hdk_archive::structs::Endianness::Big)
        } else {
            Some(hdk_archive::structs::Endianness::Little)
        };

        let reader = InnerBarReader::open(cursor, def, sig, endian)
            .map_err(|e| JsValue::from_str(&format!("Failed to open BAR: {}", e)))?;

        Ok(Bar {
            inner: Some(reader),
        })
    }

    pub fn header(&self) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        let raw = r.header();
        swb::to_value(&header_from_raw(raw))
            .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))
    }

    pub fn entry_count(&self) -> Result<usize, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        Ok(r.entry_count())
    }

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
        swb::to_value(&arr).map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))
    }

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

    pub fn close(&mut self) {
        self.inner = None;
    }
}
