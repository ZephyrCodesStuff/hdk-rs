use binrw::Endian;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use hdk_archive::sharc::builder::SharcBuilder;
use hdk_archive::structs::CompressionType;
use hdk_secure::hash::AfsHash;

#[wasm_bindgen]
pub struct SharcWriter {
    inner: Option<SharcBuilder>,
}

#[wasm_bindgen]
impl SharcWriter {
    /// Create a new in-memory SHARC writer. `key` must be 32 bytes. `big_endian` selects endianness.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8], files_key: &[u8]) -> Result<Self, JsValue> {
        if key.len() != 32 {
            return Err(JsValue::from_str("Key must be 32 bytes"));
        }

        if files_key.len() != 16 {
            return Err(JsValue::from_str("Files key must be 16 bytes"));
        }

        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| JsValue::from_str("Failed to convert key to array"))?;

        let files_key_arr: [u8; 16] = files_key
            .try_into()
            .map_err(|_| JsValue::from_str("Failed to convert files key to array"))?;

        let writer = SharcBuilder::new(key_arr, files_key_arr);

        Ok(Self {
            inner: Some(writer),
        })
    }

    /// Add an entry from bytes. `name_hash` is the AFS hash as u32, `compression_raw` is the u8 enum value.
    pub fn add_entry_from_bytes(
        &mut self,
        name_hash: u32,
        compression_raw: u8,
        data: &[u8],
        iv: &[u8],
    ) -> Result<(), JsValue> {
        if iv.len() != 8 {
            return Err(JsValue::from_str("IV must be 8 bytes"));
        }

        let w = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Writer closed"))?;

        let comp = CompressionType::try_from(compression_raw)
            .map_err(|_| JsValue::from_str("Invalid compression type"))?;
        let afs_hash = AfsHash(name_hash as i32);

        let iv_arr: [u8; 8] = iv
            .try_into()
            .map_err(|_| JsValue::from_str("Failed to convert IV to array"))?;

        w.add_entry(afs_hash, data.to_vec(), comp, iv_arr);

        Ok(())
    }

    /// Finalize and return the archive bytes as a `Uint8Array`.
    pub fn finish(&mut self, big_endian: bool) -> Result<Uint8Array, JsValue> {
        let mut writer = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("Writer closed"))?;

        let endian = if big_endian {
            Endian::Big
        } else {
            Endian::Little
        };

        let mut buf = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut buf);

        writer
            .build(&mut cursor, endian)
            .map_err(|e| JsValue::from_str(&format!("Failed to build archive: {e}")))?;

        let arr = Uint8Array::new_with_length(buf.len() as u32);
        arr.copy_from(&buf[..]);
        Ok(arr)
    }

    /// Close without finishing (drop writer)
    pub fn close(&mut self) {
        self.inner = None;
    }
}
