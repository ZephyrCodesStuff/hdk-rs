use hdk_secure::modes::{BlowfishPS3, XteaPS3};
use wasm_bindgen::prelude::*;

use cipher::{KeyIvInit, KeySizeUser, StreamCipher};
use generic_array::GenericArray;

#[wasm_bindgen]
pub enum CipherAlgorithm {
    Xtea,
    Blowfish,
}

#[wasm_bindgen]
pub fn cipher_ctr_apply(
    alg: CipherAlgorithm,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    // CTR for 64-bit block ciphers uses 8-byte IVs
    if iv.len() != 8 {
        return Err(JsValue::from_str("IV must be 8 bytes for 64-bit block CTR"));
    }

    match alg {
        CipherAlgorithm::Xtea => {
            if key.len() != XteaPS3::key_size() {
                return Err(JsValue::from_str(
                    format!("XTEA key must be {} bytes", XteaPS3::key_size()).as_str(),
                ));
            }

            let key_ga = GenericArray::from_slice(key);
            let iv_ga = GenericArray::from_slice(iv);
            let mut cipher = XteaPS3::new(key_ga, iv_ga);

            let mut out = data.to_vec();
            cipher.apply_keystream(&mut out);
            Ok(out)
        }

        CipherAlgorithm::Blowfish => {
            if key.len() != BlowfishPS3::key_size() {
                return Err(JsValue::from_str(
                    format!("Blowfish key must be {} bytes", BlowfishPS3::key_size()).as_str(),
                ));
            }

            let key_ga = GenericArray::from_slice(key);
            let iv_ga = GenericArray::from_slice(iv);
            let mut cipher = BlowfishPS3::new(key_ga, iv_ga);

            let mut out = data.to_vec();
            cipher.apply_keystream(&mut out);
            Ok(out)
        }
    }
}
