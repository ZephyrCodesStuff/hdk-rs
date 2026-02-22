use hdk_secure::modes::{BlowfishEcbDec, BlowfishPS3, XteaPS3};
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

/// Recover the Blowfish-CTR IV from the ciphertext using a known-plaintext block.
///
/// Expects `known_plaintext` to be at least 8 bytes long. Returns the 8-byte IV.
#[wasm_bindgen]
pub fn blowfish_recover_iv(
    key: &[u8],
    ciphertext: &[u8],
    known_plaintext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if ciphertext.len() < 8 {
        return Err(JsValue::from_str("Ciphertext too short for IV recovery"));
    }
    if known_plaintext.len() < 8 {
        return Err(JsValue::from_str(
            "Known plaintext must be at least 8 bytes",
        ));
    }
    if key.len() != BlowfishPS3::key_size() {
        return Err(JsValue::from_str(&format!(
            "Blowfish key must be {} bytes",
            BlowfishPS3::key_size()
        )));
    }

    // Step 1: XOR known plaintext against the first ciphertext block → ECB(IV)
    let mut ecb_iv = [0u8; 8];
    for i in 0..8 {
        ecb_iv[i] = known_plaintext[i] ^ ciphertext[i];
    }

    // Step 2: ECB-decrypt the block to get the raw IV.
    use ctr::cipher::{BlockDecryptMut, KeyInit, block_padding::NoPadding};
    let ecb_cipher = BlowfishEcbDec::new_from_slice(key)
        .map_err(|e| JsValue::from_str(&format!("Failed to create ECB cipher: {e}")))?;

    let mut block = ecb_iv;
    ecb_cipher
        .decrypt_padded_mut::<NoPadding>(&mut block)
        .map_err(|e| JsValue::from_str(&format!("ECB decrypt failed: {e}")))?;

    Ok(block.to_vec())
}
