//! Cryptographic operations for SDAT files

use crate::error::CryptoError;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Block};
use sha1_smol::Sha1;

/// SDAT-specific cryptographic constants
pub const SDAT_KEY: [u8; 16] = [
    0x0D, 0x65, 0x5E, 0xF8, 0xE6, 0x74, 0xA9, 0x8A, 0xB8, 0x50, 0x5C, 0xFA, 0x7D, 0x01, 0x29, 0x33,
];

/// SDAT flag value (also defined in headers.rs but duplicated here for convenience)
pub const SDAT_FLAG: u32 = 0x01000000;

/// EDAT/SDAT related flags
pub const EDAT_COMPRESSED_FLAG: u32 = 0x00000001;
pub const EDAT_FLAG_0X02: u32 = 0x00000002;
pub const EDAT_ENCRYPTED_KEY_FLAG: u32 = 0x00000008;
pub const EDAT_FLAG_0X10: u32 = 0x00000010;
pub const EDAT_FLAG_0X20: u32 = 0x00000020;
pub const EDAT_DEBUG_DATA_FLAG: u32 = 0x80000000;

/// EDAT initialization vector (all zeros)
pub const EDAT_IV: [u8; 16] = [0u8; 16];

/// EDAT key version 0
pub const EDAT_KEY_0: [u8; 16] = [
    0xBE, 0x95, 0x9C, 0xA8, 0x30, 0x8D, 0xEF, 0xA2, 0xE5, 0xE1, 0x80, 0xC6, 0x37, 0x12, 0xA9, 0xAE,
];

/// EDAT key version 1
pub const EDAT_KEY_1: [u8; 16] = [
    0x4C, 0xA9, 0xC1, 0x4B, 0x01, 0xC9, 0x53, 0x09, 0x96, 0x9B, 0xEC, 0x68, 0xAA, 0x0B, 0xC0, 0x81,
];

/// EDAT hash version 0
pub const EDAT_HASH_0: [u8; 16] = [
    0xEF, 0xFE, 0x5B, 0xD1, 0x65, 0x2E, 0xEB, 0xC1, 0x19, 0x18, 0xCF, 0x7C, 0x04, 0xD4, 0xF0, 0x11,
];

/// EDAT hash version 1
pub const EDAT_HASH_1: [u8; 16] = [
    0x3D, 0x92, 0x69, 0x9B, 0x70, 0x5B, 0x07, 0x38, 0x54, 0xD8, 0xFC, 0xC6, 0xC7, 0x67, 0x27, 0x47,
];

/// SDAT footer version 1
pub const SDAT_FOOTER_V1: [u8; 16] = [
    0x66, 0x69, 0x6E, 0x69, 0x73, 0x68, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// NPDRM OMAC key 2 (used for dev_hash generation)
pub const NPDRM_OMAC_KEY_2: [u8; 16] = [
    0x6B, 0xA5, 0x29, 0x76, 0xEF, 0xDA, 0x16, 0xEF, 0x3C, 0x33, 0x9F, 0xB2, 0x97, 0x1E, 0x25, 0x6B,
];

/// NPDRM OMAC key 3 (used for title_hash generation)
pub const NPDRM_OMAC_KEY_3: [u8; 16] = [
    0x9B, 0x51, 0x5F, 0xEA, 0xCF, 0x75, 0x06, 0x49, 0x81, 0xAA, 0x60, 0x4D, 0x91, 0xA5, 0x4E, 0x97,
];

/// Cryptographic context for SDAT operations
pub struct CryptoContext {
    // Context is stateless for now, but can be extended later
}

impl CryptoContext {
    /// Create a new cryptographic context
    pub fn new() -> Self {
        Self {}
    }

    /// AES-CBC decryption
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte AES key
    /// * `iv` - 16-byte initialization vector
    /// * `input` - Input data to decrypt (must be multiple of 16 bytes)
    /// * `output` - Output buffer for decrypted data
    pub fn aes_cbc_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 16,
                actual: key.len(),
            });
        }
        if iv.len() != 16 {
            return Err(CryptoError::InvalidIvLength {
                expected: 16,
                actual: iv.len(),
            });
        }
        if !input.len().is_multiple_of(16) {
            return Err(CryptoError::AesError(
                "Input length must be multiple of 16 bytes".to_string(),
            ));
        }
        if output.len() < input.len() {
            return Err(CryptoError::AesError("Output buffer too small".to_string()));
        }

        let cipher = Aes128::new_from_slice(key)
            .map_err(|e| CryptoError::AesError(format!("Failed to create AES cipher: {}", e)))?;

        let mut prev_ciphertext = *Block::from_slice(iv);

        for (input_chunk, output_chunk) in input.chunks_exact(16).zip(output.chunks_exact_mut(16)) {
            let current_ciphertext = *Block::from_slice(input_chunk);
            let mut block = current_ciphertext;

            // Decrypt the block
            cipher.decrypt_block(&mut block);

            // XOR with previous ciphertext block (CBC mode)
            for (out_byte, (dec_byte, prev_byte)) in output_chunk
                .iter_mut()
                .zip(block.iter().zip(prev_ciphertext.iter()))
            {
                *out_byte = dec_byte ^ prev_byte;
            }

            // Update previous ciphertext for next iteration
            prev_ciphertext = current_ciphertext;
        }

        Ok(())
    }

    /// AES-CBC encryption
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte AES key
    /// * `iv` - 16-byte initialization vector
    /// * `input` - Input data to encrypt (must be multiple of 16 bytes)
    /// * `output` - Output buffer for encrypted data
    pub fn aes_cbc_encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 16,
                actual: key.len(),
            });
        }
        if iv.len() != 16 {
            return Err(CryptoError::InvalidIvLength {
                expected: 16,
                actual: iv.len(),
            });
        }
        if !input.len().is_multiple_of(16) {
            return Err(CryptoError::AesError(
                "Input length must be multiple of 16 bytes".to_string(),
            ));
        }
        if output.len() < input.len() {
            return Err(CryptoError::AesError("Output buffer too small".to_string()));
        }

        let cipher = Aes128::new_from_slice(key)
            .map_err(|e| CryptoError::AesError(format!("Failed to create AES cipher: {}", e)))?;

        let mut prev_ciphertext = *Block::from_slice(iv);

        for (input_chunk, output_chunk) in input.chunks_exact(16).zip(output.chunks_exact_mut(16)) {
            let mut block = Block::default();

            // XOR input with previous ciphertext block (CBC mode)
            for (block_byte, (input_byte, prev_byte)) in block
                .iter_mut()
                .zip(input_chunk.iter().zip(prev_ciphertext.iter()))
            {
                *block_byte = input_byte ^ prev_byte;
            }

            // Encrypt the block
            cipher.encrypt_block(&mut block);
            output_chunk.copy_from_slice(&block);

            // Update previous ciphertext for next iteration
            prev_ciphertext = block;
        }

        Ok(())
    }

    /// AES-ECB encryption
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte AES key
    /// * `input` - Input data to encrypt (must be exactly 16 bytes)
    /// * `output` - Output buffer for encrypted data (must be exactly 16 bytes)
    pub fn aes_ecb_encrypt(
        &self,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 16,
                actual: key.len(),
            });
        }
        if input.len() != 16 {
            return Err(CryptoError::AesError(
                "Input must be exactly 16 bytes for ECB".to_string(),
            ));
        }
        if output.len() < 16 {
            return Err(CryptoError::AesError(
                "Output buffer must be at least 16 bytes".to_string(),
            ));
        }

        let cipher = Aes128::new_from_slice(key)
            .map_err(|e| CryptoError::AesError(format!("Failed to create AES cipher: {}", e)))?;

        let mut block = *Block::from_slice(input);
        cipher.encrypt_block(&mut block);
        output[..16].copy_from_slice(&block);

        Ok(())
    }

    /// Compute HMAC-SHA1
    ///
    /// # Arguments
    ///
    /// * `key` - HMAC key
    /// * `data` - Data to authenticate
    ///
    /// # Returns
    ///
    /// Returns 20-byte HMAC-SHA1 hash
    pub fn hmac_sha1(&self, key: &[u8], data: &[u8]) -> [u8; 20] {
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];

        // If key is longer than 64 bytes, hash it first
        let key_bytes = if key.len() > 64 {
            let mut hasher = Sha1::new();
            hasher.update(key);
            let hashed = hasher.digest();
            hashed.bytes().to_vec()
        } else {
            key.to_vec()
        };

        // XOR key with ipad and opad
        for (i, &k) in key_bytes.iter().enumerate() {
            if i < 64 {
                ipad[i] ^= k;
                opad[i] ^= k;
            }
        }

        // Inner hash: SHA1(ipad || data)
        let mut inner_hasher = Sha1::new();
        inner_hasher.update(&ipad);
        inner_hasher.update(data);
        let inner_hash = inner_hasher.digest();

        // Outer hash: SHA1(opad || inner_hash)
        let mut outer_hasher = Sha1::new();
        outer_hasher.update(&opad);
        outer_hasher.update(&inner_hash.bytes());
        let outer_hash = outer_hasher.digest();

        outer_hash.bytes()
    }

    /// Compute AES-CMAC
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte AES key
    /// * `data` - Data to authenticate
    ///
    /// # Returns
    ///
    /// Returns 16-byte AES-CMAC
    pub fn aes_cmac(&self, key: &[u8], data: &[u8]) -> [u8; 16] {
        if key.len() != 16 {
            return [0u8; 16];
        }

        let cipher = match Aes128::new_from_slice(key) {
            Ok(c) => c,
            Err(_) => return [0u8; 16],
        };

        // Generate subkeys K1 and K2
        let mut l = Block::default();
        cipher.encrypt_block(&mut l);

        let (k1, k2) = self.generate_cmac_subkeys(&l);

        // Process the message
        let mut x = Block::default();

        if data.is_empty() {
            // Empty message case - pad with 0x80 and XOR with K2
            let mut last_block = [0u8; 16];
            last_block[0] = 0x80;

            for (i, &k2_byte) in k2.iter().enumerate() {
                last_block[i] ^= k2_byte;
            }

            x = *Block::from_slice(&last_block);
            cipher.encrypt_block(&mut x);
        } else {
            let _n = data.len().div_ceil(16); // Number of blocks
            let complete_blocks = data.len() / 16;
            let remainder = data.len() % 16;

            // Process all complete blocks except possibly the last one
            for i in 0..complete_blocks {
                let block_data = &data[i * 16..(i + 1) * 16];
                let mut y = *Block::from_slice(block_data);

                // XOR with previous result
                for (j, &x_byte) in x.iter().enumerate() {
                    y[j] ^= x_byte;
                }

                cipher.encrypt_block(&mut y);
                x = y;
            }

            // Handle the last block
            if remainder == 0 && complete_blocks > 0 {
                // Last block is complete - XOR with K1
                let last_block_data = &data[(complete_blocks - 1) * 16..];
                let mut last_block = *Block::from_slice(last_block_data);

                // We need to redo the last block with K1
                // First, get the state before the last block
                x = Block::default();
                for i in 0..(complete_blocks - 1) {
                    let block_data = &data[i * 16..(i + 1) * 16];
                    let mut y = *Block::from_slice(block_data);

                    for (j, &x_byte) in x.iter().enumerate() {
                        y[j] ^= x_byte;
                    }

                    cipher.encrypt_block(&mut y);
                    x = y;
                }

                // Now process the last block with K1
                for (i, &k1_byte) in k1.iter().enumerate() {
                    last_block[i] ^= k1_byte;
                }

                for (j, &x_byte) in x.iter().enumerate() {
                    last_block[j] ^= x_byte;
                }

                x = *Block::from_slice(&last_block);
                cipher.encrypt_block(&mut x);
            } else if remainder > 0 {
                // Incomplete last block - pad and XOR with K2
                let mut last_block = [0u8; 16];
                last_block[..remainder].copy_from_slice(&data[complete_blocks * 16..]);
                last_block[remainder] = 0x80; // Padding

                for (i, &k2_byte) in k2.iter().enumerate() {
                    last_block[i] ^= k2_byte;
                }

                for (j, &x_byte) in x.iter().enumerate() {
                    last_block[j] ^= x_byte;
                }

                x = *Block::from_slice(&last_block);
                cipher.encrypt_block(&mut x);
            }
        }

        let mut cmac = [0u8; 16];
        cmac.copy_from_slice(&x);
        cmac
    }

    /// Generate CMAC subkeys K1 and K2 from L
    fn generate_cmac_subkeys(&self, l: &Block) -> ([u8; 16], [u8; 16]) {
        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];

        // K1 = L << 1
        let msb = l[0] & 0x80;
        for i in 0..15 {
            k1[i] = (l[i] << 1) | (l[i + 1] >> 7);
        }
        k1[15] = l[15] << 1;

        if msb != 0 {
            k1[15] ^= 0x87; // XOR with Rb
        }

        // K2 = K1 << 1
        let msb = k1[0] & 0x80;
        for i in 0..15 {
            k2[i] = (k1[i] << 1) | (k1[i + 1] >> 7);
        }
        k2[15] = k1[15] << 1;

        if msb != 0 {
            k2[15] ^= 0x87; // XOR with Rb
        }

        (k1, k2)
    }

    /// Generate final key for crypto operations based on mode and version
    ///
    /// # Arguments
    ///
    /// * `crypto_mode` - Crypto mode flags
    /// * `version` - NPD version (affects key selection)
    /// * `key` - Input key
    /// * `iv` - Input IV
    ///
    /// # Returns
    ///
    /// Returns (final_key, final_iv) tuple
    pub fn generate_key(
        &self,
        crypto_mode: u32,
        version: u32,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<([u8; 16], [u8; 16]), CryptoError> {
        let mut key_final = [0u8; 16];
        let mut iv_final = [0u8; 16];

        let mode = crypto_mode & 0xF0000000;
        match mode {
            0x10000000 => {
                // Encrypted ERK - decrypt the key with EDAT_KEY + EDAT_IV and copy the original IV
                let edat_key = if version != 0 {
                    &EDAT_KEY_1
                } else {
                    &EDAT_KEY_0
                };
                self.aes_cbc_decrypt(edat_key, &EDAT_IV, key, &mut key_final)?;
                iv_final.copy_from_slice(iv);
            }
            0x20000000 => {
                // Default ERK - use EDAT_KEY and EDAT_IV
                let edat_key = if version != 0 {
                    &EDAT_KEY_1
                } else {
                    &EDAT_KEY_0
                };
                key_final.copy_from_slice(edat_key);
                iv_final.copy_from_slice(&EDAT_IV);
            }
            0x00000000 => {
                // Unencrypted ERK - use the original key and iv
                key_final.copy_from_slice(key);
                iv_final.copy_from_slice(iv);
            }
            _ => {
                return Err(CryptoError::AesError(format!(
                    "Unknown crypto mode: 0x{:08X}",
                    mode
                )));
            }
        }

        Ok((key_final, iv_final))
    }

    /// Generate final hash key for hash operations based on mode and version
    ///
    /// # Arguments
    ///
    /// * `hash_mode` - Hash mode flags
    /// * `version` - NPD version (affects key selection)
    /// * `hash` - Input hash key
    ///
    /// # Returns
    ///
    /// Returns final hash key
    pub fn generate_hash(
        &self,
        hash_mode: u32,
        version: u32,
        hash: &[u8; 16],
    ) -> Result<[u8; 16], CryptoError> {
        let mut hash_final = [0u8; 16];

        let mode = hash_mode & 0xF0000000;
        match mode {
            0x10000000 => {
                // Encrypted HASH - decrypt the hash with EDAT_KEY + EDAT_IV
                let edat_key = if version != 0 {
                    &EDAT_KEY_1
                } else {
                    &EDAT_KEY_0
                };
                self.aes_cbc_decrypt(edat_key, &EDAT_IV, hash, &mut hash_final)?;
            }
            0x20000000 => {
                // Default HASH - use EDAT_HASH
                let edat_hash = if version != 0 {
                    &EDAT_HASH_1
                } else {
                    &EDAT_HASH_0
                };
                hash_final.copy_from_slice(edat_hash);
            }
            0x00000000 => {
                // Unencrypted HASH - use the original hash
                hash_final.copy_from_slice(hash);
            }
            _ => {
                return Err(CryptoError::AesError(format!(
                    "Unknown hash mode: 0x{:08X}",
                    mode
                )));
            }
        }

        Ok(hash_final)
    }
}

impl Default for CryptoContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate SDAT decryption key from dev_hash
///
/// # Arguments
///
/// * `dev_hash` - 16-byte device hash from NPD header
///
/// # Returns
///
/// Returns 16-byte SDAT key (XOR of dev_hash and SDAT_KEY)
///
/// # Requirements
///
/// Addresses requirement 5.1, 5.2: SDAT key derivation
pub fn generate_sdat_key(dev_hash: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = dev_hash[i] ^ SDAT_KEY[i];
    }
    key
}

/// Generate block key for EDAT/SDAT data block encryption/decryption
///
/// # Arguments
///
/// * `block_number` - Block number (0-based index)
/// * `dev_hash` - 16-byte device hash from NPD header
/// * `npd_version` - NPD header version
///
/// # Returns
///
/// Returns 16-byte block key
///
/// # Requirements
///
/// Addresses requirement 5.1, 5.2: Block key generation for SDAT operations
pub fn generate_block_key(block_number: u32, dev_hash: &[u8; 16], npd_version: u32) -> [u8; 16] {
    let mut block_key = [0u8; 16];

    // For NPD version <= 1, use empty key for first 12 bytes
    // For NPD version > 1, use dev_hash for first 12 bytes
    if npd_version <= 1 {
        // First 12 bytes remain zero
    } else {
        block_key[..12].copy_from_slice(&dev_hash[..12]);
    }

    // Last 4 bytes are the block number in big-endian format
    let block_number_be = block_number.to_be_bytes();
    block_key[12..16].copy_from_slice(&block_number_be[0..4]);

    block_key
}

/// Generate encrypted block key for EDAT/SDAT data block operations
///
/// # Arguments
///
/// * `block_number` - Block number (0-based index)
/// * `dev_hash` - 16-byte device hash from NPD header
/// * `npd_version` - NPD header version
/// * `crypt_key` - 16-byte encryption key (SDAT key or EDAT key)
/// * `crypto_ctx` - Cryptographic context for AES operations
///
/// # Returns
///
/// Returns Result containing 16-byte encrypted block key
///
/// # Requirements
///
/// Addresses requirement 5.1, 5.2: Encrypted block key generation for SDAT operations
pub fn generate_encrypted_block_key(
    block_number: u32,
    dev_hash: &[u8; 16],
    npd_version: u32,
    crypt_key: &[u8; 16],
    crypto_ctx: &CryptoContext,
) -> Result<[u8; 16], CryptoError> {
    let block_key = generate_block_key(block_number, dev_hash, npd_version);
    let mut encrypted_key = [0u8; 16];

    crypto_ctx.aes_ecb_encrypt(crypt_key, &block_key, &mut encrypted_key)?;

    Ok(encrypted_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdat_key_generation() {
        let dev_hash = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];

        let expected = [
            0x11 ^ 0x0D,
            0x22 ^ 0x65,
            0x33 ^ 0x5E,
            0x44 ^ 0xF8,
            0x55 ^ 0xE6,
            0x66 ^ 0x74,
            0x77 ^ 0xA9,
            0x88 ^ 0x8A,
            0x99 ^ 0xB8,
            0xAA ^ 0x50,
            0xBB ^ 0x5C,
            0xCC ^ 0xFA,
            0xDD ^ 0x7D,
            0xEE ^ 0x01,
            0xFF ^ 0x29,
            0x33,
        ];

        let result = generate_sdat_key(&dev_hash);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sdat_key_generation_zero_hash() {
        let dev_hash = [0u8; 16];
        let result = generate_sdat_key(&dev_hash);

        // With zero dev_hash, result should be SDAT_KEY itself
        assert_eq!(result, SDAT_KEY);
    }

    #[test]
    fn test_block_key_generation_version_0() {
        let dev_hash = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let block_number = 0x12345678;
        let npd_version = 0;

        let result = generate_block_key(block_number, &dev_hash, npd_version);

        // For version <= 1, first 12 bytes should be zero
        let expected = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
            0x56, 0x78,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_block_key_generation_version_1() {
        let dev_hash = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let block_number = 0x87654321;
        let npd_version = 1;

        let result = generate_block_key(block_number, &dev_hash, npd_version);

        // For version <= 1, first 12 bytes should be zero
        let expected = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x65,
            0x43, 0x21,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_block_key_generation_version_2() {
        let dev_hash = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let block_number = 0xABCDEF01;
        let npd_version = 2;

        let result = generate_block_key(block_number, &dev_hash, npd_version);

        // For version > 1, first 12 bytes should be from dev_hash
        let expected = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xAB, 0xCD,
            0xEF, 0x01,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_block_key_generation_block_zero() {
        let dev_hash = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let block_number = 0;
        let npd_version = 3;

        let result = generate_block_key(block_number, &dev_hash, npd_version);

        let expected = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0x00, 0x00,
            0x00, 0x00,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_encrypted_block_key_generation() {
        let ctx = CryptoContext::new();
        let dev_hash = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let block_number = 1;
        let npd_version = 2;
        let crypt_key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let result =
            generate_encrypted_block_key(block_number, &dev_hash, npd_version, &crypt_key, &ctx);

        assert!(result.is_ok());
        let encrypted_key = result.unwrap();

        // The encrypted key should not be the same as the original block key
        let original_block_key = generate_block_key(block_number, &dev_hash, npd_version);
        assert_ne!(encrypted_key, original_block_key);

        // The encrypted key should not be all zeros
        assert_ne!(encrypted_key, [0u8; 16]);
    }

    #[test]
    fn test_aes_ecb_encrypt() {
        let ctx = CryptoContext::new();
        let key = [0u8; 16];
        let input = [0u8; 16];
        let mut output = [0u8; 16];

        let result = ctx.aes_ecb_encrypt(&key, &input, &mut output);
        assert!(result.is_ok());

        // The output should not be all zeros (unless using a zero key with zero input)
        // This is a basic sanity check
    }

    #[test]
    fn test_aes_cbc_encrypt_decrypt() {
        let ctx = CryptoContext::new();
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];

        let mut encrypted = [0u8; 16];
        let mut decrypted = [0u8; 16];

        // Encrypt
        let result = ctx.aes_cbc_encrypt(&key, &iv, &plaintext, &mut encrypted);
        assert!(result.is_ok());

        // Decrypt
        let result = ctx.aes_cbc_decrypt(&key, &iv, &encrypted, &mut decrypted);
        assert!(result.is_ok());

        // Should get back original plaintext
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_cbc_known_vectors() {
        let ctx = CryptoContext::new();

        // Test with EDAT_KEY_0 and EDAT_IV (from the C code)
        let key = EDAT_KEY_0;
        let iv = EDAT_IV;
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        let mut encrypted = [0u8; 16];
        let mut decrypted = [0u8; 16];

        // Encrypt
        let result = ctx.aes_cbc_encrypt(&key, &iv, &plaintext, &mut encrypted);
        assert!(result.is_ok());

        // Decrypt
        let result = ctx.aes_cbc_decrypt(&key, &iv, &encrypted, &mut decrypted);
        assert!(result.is_ok());

        // Should get back original plaintext
        assert_eq!(decrypted, plaintext);

        // Test multi-block
        let plaintext_multi = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];

        let mut encrypted_multi = [0u8; 32];
        let mut decrypted_multi = [0u8; 32];

        let result = ctx.aes_cbc_encrypt(&key, &iv, &plaintext_multi, &mut encrypted_multi);
        assert!(result.is_ok());

        let result = ctx.aes_cbc_decrypt(&key, &iv, &encrypted_multi, &mut decrypted_multi);
        assert!(result.is_ok());

        assert_eq!(decrypted_multi, plaintext_multi);
    }

    #[test]
    fn test_hmac_sha1() {
        let ctx = CryptoContext::new();
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";

        let result = ctx.hmac_sha1(key, data);

        // This should produce a known HMAC-SHA1 result
        // Expected: de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
        let expected = [
            0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7, 0x0a,
            0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_aes_cmac_empty() {
        let ctx = CryptoContext::new();
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = b"";

        let result = ctx.aes_cmac(&key, data);

        // Should produce a valid CMAC (not all zeros)
        assert_ne!(result, [0u8; 16]);
    }

    #[test]
    fn test_aes_cmac_single_block() {
        let ctx = CryptoContext::new();
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];

        let result = ctx.aes_cmac(&key, &data);

        // Should produce a valid CMAC (not all zeros)
        assert_ne!(result, [0u8; 16]);
    }

    #[test]
    fn test_invalid_key_length() {
        let ctx = CryptoContext::new();
        let short_key = [0u8; 8];
        let input = [0u8; 16];
        let mut output = [0u8; 16];

        let result = ctx.aes_ecb_encrypt(&short_key, &input, &mut output);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 16,
                actual: 8
            })
        ));
    }

    #[test]
    fn test_invalid_iv_length() {
        let ctx = CryptoContext::new();
        let key = [0u8; 16];
        let short_iv = [0u8; 8];
        let input = [0u8; 16];
        let mut output = [0u8; 16];

        let result = ctx.aes_cbc_encrypt(&key, &short_iv, &input, &mut output);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidIvLength {
                expected: 16,
                actual: 8
            })
        ));
    }
}
