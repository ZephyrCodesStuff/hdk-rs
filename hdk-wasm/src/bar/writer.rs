use js_sys::Uint8Array;
use std::io::Cursor;
use wasm_bindgen::prelude::*;

use binrw::Endian;
use hdk_archive::bar::builder::BarBuilder;
use hdk_archive::structs::CompressionType;
use hdk_secure::hash::AfsHash;

#[wasm_bindgen]
pub struct BarWriter {
    #[wasm_bindgen(skip)]
    inner: Option<BarBuilder>,
}

#[wasm_bindgen]
impl BarWriter {
    #[wasm_bindgen(constructor)]
    pub fn new(default_key: &[u8], signature_key: &[u8]) -> Result<Self, JsValue> {
        if default_key.len() != 32 || signature_key.len() != 32 {
            return Err(JsValue::from_str("Keys must be 32 bytes"));
        }
        let mut def = [0u8; 32];
        def.copy_from_slice(&default_key[..32]);
        let mut sig = [0u8; 32];
        sig.copy_from_slice(&signature_key[..32]);

        let builder = BarBuilder::new(def, sig);
        Ok(Self {
            inner: Some(builder),
        })
    }

    pub fn add_entry_from_bytes(
        &mut self,
        name_hash: u32,
        compression_raw: u8,
        data: &[u8],
    ) -> Result<(), JsValue> {
        let b = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("Writer closed"))?;
        let comp = CompressionType::try_from(compression_raw)
            .map_err(|_| JsValue::from_str("Invalid compression type"))?;
        let ah = AfsHash(name_hash as i32);
        b.add_entry(ah, data.to_vec(), comp);
        Ok(())
    }

    pub fn finish(mut self) -> Result<Uint8Array, JsValue> {
        let mut builder = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("Writer closed"))?;

        let mut cursor = Cursor::new(Vec::new());
        builder
            .build(&mut cursor, Endian::Little)
            .map_err(|e| JsValue::from_str(&format!("finish failed: {}", e)))?;

        let vec = cursor.into_inner();
        let arr = Uint8Array::new_with_length(vec.len() as u32);
        arr.copy_from(&vec[..]);
        Ok(arr)
    }

    pub fn close(&mut self) {
        self.inner = None;
    }
}
