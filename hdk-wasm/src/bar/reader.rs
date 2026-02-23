use binrw::BinRead;
use wasm_bindgen::prelude::*;

use std::io::{Cursor, Read};

use hdk_archive::bar::structs::BarArchive as InnerBarArchive;
use hdk_archive::structs::Endianness;
use js_sys::{Array as JsArray, Uint8Array};
use serde_wasm_bindgen as swb;

use crate::bar::structs::Bar;

#[wasm_bindgen]
impl Bar {
    #[wasm_bindgen(constructor)]
    pub fn new(
        buf: &[u8],
        default_key: &[u8],
        signature_key: &[u8],
        big_endian: bool,
    ) -> Result<Self, JsValue> {
        if default_key.len() != 32 || signature_key.len() != 32 {
            return Err(JsValue::from_str("Keys must be 32 bytes"));
        }

        let mut def = [0u8; 32];
        def.copy_from_slice(&default_key[..32]);
        let mut sig = [0u8; 32];
        sig.copy_from_slice(&signature_key[..32]);

        let mut cursor = Cursor::new(buf.to_vec());

        let endian = if big_endian {
            Endianness::Big
        } else {
            Endianness::Little
        };

        let archive = match endian {
            Endianness::Big => {
                InnerBarArchive::read_be_args(&mut cursor, (def, sig, buf.len() as u32))
            }
            Endianness::Little => {
                InnerBarArchive::read_le_args(&mut cursor, (def, sig, buf.len() as u32))
            }
        }
        .map_err(|e| JsValue::from_str(&format!("Failed to open BAR: {}", e)))?;

        Ok(Self {
            inner: Some(archive),
            reader: Cursor::new(buf.to_vec()),
            default_key: def,
            signature_key: sig,
        })
    }

    pub fn header(&self) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        let js = swb::to_value(&crate::bar::structs::header_from_raw(r))
            .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?;
        Ok(js)
    }

    pub fn entry_count(&self) -> Result<usize, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        Ok(r.archive_data.file_count as usize)
    }

    pub fn list_toc(&self) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        let arr: Vec<crate::bar::structs::BarEntryMetadata> = r
            .entries
            .iter()
            .map(crate::bar::structs::meta_from_raw)
            .collect();

        let js = swb::to_value(&arr)
            .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?;
        Ok(js)
    }

    pub fn read_entry(&mut self, index: usize) -> Result<Vec<u8>, JsValue> {
        let r = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let entry = r
            .entries
            .get(index)
            .ok_or_else(|| JsValue::from_str("Index out of bounds"))?;

        let entry_data = r
            .entry_data(
                &mut self.reader,
                entry,
                &self.default_key,
                &self.signature_key,
            )
            .map_err(|e| JsValue::from_str(&format!("Failed to read entry data: {}", e)))?;

        Ok(entry_data)
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

        let entry = r
            .entries
            .get(index)
            .ok_or_else(|| JsValue::from_str("Index out of bounds"))?;

        let entry_data = r
            .entry_data(
                &mut self.reader,
                entry,
                &self.default_key,
                &self.signature_key,
            )
            .map_err(|e| JsValue::from_str(&format!("Failed to read entry data: {}", e)))?;

        let js_arr = JsArray::new();
        let mut buf = vec![0u8; chunk_size];

        let mut cursor = Cursor::new(entry_data);
        loop {
            match cursor.read(&mut buf) {
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
