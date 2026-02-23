use binrw::{BinRead, Endian};
use wasm_bindgen::prelude::*;

use std::io::{Cursor, Read};

use crate::{magic_to_endianess, sharc::structs::Sharc};
use hdk_archive::sharc::structs::SharcArchive;

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

        if buf.len() < 4 {
            return Err(JsValue::from_str("Buf cannot be less than 4 bytes"));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key[..32]);

        let magic: [u8; 4] = buf[0..4].try_into().expect("not enough bytes");
        let endian: Endian = magic_to_endianess(&magic).into();

        let mut cursor = Cursor::new(buf.to_vec());

        let key: [u8; 32] = key.try_into().unwrap();
        let archive = match endian {
            Endian::Big => SharcArchive::read_be_args(&mut cursor, (key, buf.len() as u32)),
            Endian::Little => SharcArchive::read_le_args(&mut cursor, (key, buf.len() as u32)),
        }
        .map_err(|e| JsValue::from_str(&format!("Failed to open SHARC: {}", e)))?;

        Ok(Self {
            inner: Some(archive),
            reader: Cursor::new(buf.to_vec()),
        })
    }

    /// Return the parsed header as a JS value (serializable object)
    pub fn header(&self) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let js = swb::to_value(&super::structs::SharcHeader {
            version: r.archive_info.version,
            flags: r.archive_info.flags,
            iv: r.iv,
            priority: r.archive_data.priority,
            timestamp: r.archive_data.timestamp,
            file_count: r.archive_data.file_count,
            files_key: r.archive_data.key,
        })
        .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?;
        Ok(js)
    }

    /// Number of entries in the archive
    pub fn entry_count(&self) -> Result<usize, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;
        Ok(r.archive_data.file_count as usize)
    }

    /// Get metadata for a single entry
    pub fn entry_metadata(&self, index: usize) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let entry = r
            .entries
            .get(index)
            .ok_or_else(|| JsValue::from_str("Index out of bounds"))?;

        let js = swb::to_value(&super::structs::SharcEntryMetadata {
            name_hash: format!("{:08x}", entry.name_hash.0),
            offset: entry.location.0,
            compression_raw: entry.location.1 as u8,
            uncompressed_size: entry.uncompressed_size,
            compressed_size: entry.compressed_size,
            iv: entry.iv,
        })
        .map_err(|e| JsValue::from_str(&format!("serialization failed: {}", e)))?;
        Ok(js)
    }

    /// Return the entire TOC as a JS array of metadata objects.
    pub fn list_toc(&self) -> Result<JsValue, JsValue> {
        let r = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Reader closed"))?;

        let arr: Vec<super::structs::SharcEntryMetadata> = r
            .entries
            .iter()
            .map(|entry| super::structs::SharcEntryMetadata {
                name_hash: format!("{:08x}", entry.name_hash.0),
                offset: entry.location.0,
                compression_raw: entry.location.1 as u8,
                uncompressed_size: entry.uncompressed_size,
                compressed_size: entry.compressed_size,
                iv: entry.iv,
            })
            .collect();

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

        let entry = r
            .entries
            .get(index)
            .ok_or_else(|| JsValue::from_str("Index out of bounds"))?;

        let entry_data = r
            .entry_data(&mut self.reader, entry)
            .map_err(|e| JsValue::from_str(&format!("Failed to read entry data: {}", e)))?;

        let js_arr = JsArray::new();
        let mut buf = vec![0u8; chunk_size];

        let mut cursor = Cursor::new(entry_data);
        loop {
            let n = cursor
                .read(&mut buf)
                .map_err(|e| JsValue::from_str(&format!("Failed to read chunk: {}", e)))?;
            if n == 0 {
                break;
            }
            let chunk = Uint8Array::new_with_length(n as u32);
            chunk.copy_from(&buf[..n]);
            js_arr.push(&chunk);
        }

        Ok(JsValue::from(js_arr))
    }

    /// Read an entry fully into memory and return the bytes.
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
            .entry_data(&mut self.reader, entry)
            .map_err(|e| JsValue::from_str(&format!("Failed to read entry data: {}", e)))?;

        let mut out = Vec::new();
        let mut cursor = Cursor::new(entry_data);

        cursor
            .read_to_end(&mut out)
            .map_err(|e| JsValue::from_str(&format!("Failed to read entry: {}", e)))?;

        Ok(out)
    }

    /// Consume the reader and free resources.
    pub fn close(&mut self) {
        self.inner = None;
    }
}
