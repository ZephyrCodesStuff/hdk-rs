use hdk_archive::mapper::{get_common_mappings, scan_content_for_paths};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmMapper {
    uuid: Option<String>,
    full: bool,
    // Store mappings as Hash(String) -> Path(String)
    mappings: HashMap<String, String>,
}

#[wasm_bindgen]
impl WasmMapper {
    #[wasm_bindgen(constructor)]
    pub fn new(uuid: Option<String>, full: bool) -> Self {
        let mut mappings = HashMap::new();

        // Initialize with common mappings
        let common = get_common_mappings(uuid.as_deref());
        for (hash, path) in common {
            // Convert AfsHash to its hex string representation to easily pass to JS
            mappings.insert(format!("{:08x}", hash.0 as u32), path);
        }

        Self {
            uuid,
            full,
            mappings,
        }
    }

    /// Scans a byte buffer and adds any found paths to the internal dictionary
    pub fn scan(&mut self, data: &[u8]) {
        let local_matches = scan_content_for_paths(data, self.uuid.as_deref(), self.full);

        for (hash, path) in local_matches {
            self.mappings.insert(format!("{:08x}", hash.0 as u32), path);
        }
    }

    /// Returns the accumulated mappings as a JavaScript Object (HashHex -> Path)
    pub fn get_mappings(&self) -> Result<js_sys::Object, JsValue> {
        let result = js_sys::Object::new();

        for (hash_hex, path) in &self.mappings {
            js_sys::Reflect::set(
                &result,
                &JsValue::from_str(hash_hex),
                &JsValue::from_str(path),
            )
            .map_err(|_| JsValue::from_str("Failed to build mapping object"))?;
        }

        Ok(result)
    }
}
