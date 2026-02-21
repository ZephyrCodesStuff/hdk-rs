use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use hdk_sdat::crypto::SdatKeys;

#[wasm_bindgen]
pub struct SdatWriter {
    #[wasm_bindgen(skip)]
    inner: Option<hdk_sdat::writer::SdatWriter>,
}

#[wasm_bindgen]
impl SdatWriter {
    #[wasm_bindgen(constructor)]
    pub fn new(output_file_name: &str, keys: &[u8]) -> Result<SdatWriter, JsValue> {
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

        let w = hdk_sdat::writer::SdatWriter::new(output_file_name, sdat_keys)
            .map_err(|e| JsValue::from_str(&format!("Failed to create writer: {}", e)))?;

        Ok(SdatWriter { inner: Some(w) })
    }

    /// Repack plaintext bytes into an SDAT container and return bytes as Uint8Array.
    pub fn write_from_bytes(&self, input: &[u8]) -> Result<Uint8Array, JsValue> {
        let w = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Writer closed"))?;

        let out = w
            .write_to_vec(input)
            .map_err(|e| JsValue::from_str(&format!("write failed: {}", e)))?;

        let arr = Uint8Array::new_with_length(out.len() as u32);
        arr.copy_from(&out[..]);
        Ok(arr)
    }

    pub fn close(&mut self) {
        self.inner = None;
    }
}
