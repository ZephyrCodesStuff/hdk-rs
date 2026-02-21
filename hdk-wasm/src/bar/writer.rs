use js_sys::Uint8Array;
use std::io::Cursor;
use wasm_bindgen::prelude::*;

use hdk_archive::bar::writer::BarWriter as InnerBarWriter;
use hdk_archive::structs::CompressionType;
use hdk_secure::hash::AfsHash;

#[wasm_bindgen]
pub struct BarWriter {
    #[wasm_bindgen(skip)]
    inner: Option<InnerBarWriter<Cursor<Vec<u8>>>>,
}

#[wasm_bindgen]
impl BarWriter {
    #[wasm_bindgen(constructor)]
    pub fn new(default_key: &[u8], signature_key: &[u8]) -> Result<BarWriter, JsValue> {
        if default_key.len() != 32 || signature_key.len() != 32 {
            return Err(JsValue::from_str("Keys must be 32 bytes"));
        }
        let mut def = [0u8; 32];
        def.copy_from_slice(&default_key[..32]);
        let mut sig = [0u8; 32];
        sig.copy_from_slice(&signature_key[..32]);

        let cursor = Cursor::new(Vec::new());
        let writer = InnerBarWriter::new(cursor, def, sig)
            .map_err(|e| JsValue::from_str(&format!("Failed to create writer: {}", e)))?;
        Ok(BarWriter {
            inner: Some(writer),
        })
    }

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
        w.add_entry_from_reader(ah, comp, &mut &data[..])
            .map_err(|e| JsValue::from_str(&format!("add entry failed: {}", e)))
    }

    pub fn finish(mut self) -> Result<Uint8Array, JsValue> {
        let writer = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("Writer closed"))?;
        let out = writer
            .finish()
            .map_err(|e| JsValue::from_str(&format!("finish failed: {}", e)))?;
        let vec = out.into_inner();
        let arr = Uint8Array::new_with_length(vec.len() as u32);
        arr.copy_from(&vec[..]);
        Ok(arr)
    }

    pub fn close(&mut self) {
        self.inner = None;
    }
}
