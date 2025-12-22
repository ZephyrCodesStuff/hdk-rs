#[cfg(test)]
mod tests {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit};

    #[test]
    fn test_xtea_basic() {
        let key = GenericArray::from([0u8; 16]); // All zero key
        let cipher = crate::xtea::Xtea::new(&key);

        let mut block = GenericArray::from([0u8; 8]);
        cipher.encrypt_block(&mut block);
        let encrypted = block.clone(); // Not cloning this will simply create a reference

        // Decrypt
        cipher.decrypt_block(&mut block);
        assert_eq!(block, GenericArray::from([0u8; 8]));

        // Ensure some encryption happened
        assert_ne!(encrypted, GenericArray::from([0u8; 8]));
    }

    #[test]
    fn test_xtea_roundtrip() {
        let key = GenericArray::from([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        let cipher = crate::xtea::Xtea::new(&key);

        let plaintext = b"Hello, World! This is a test message for XTEA encryption.";
        // We will test block-by-block encryption/decryption since we implemented BlockCipher
        // Note: The user's test used CTR mode with consistent IV.
        // Since we verify BlockCipher E(k, x) and D(k, x), we verify the core.
        // CTR is built on top.

        let mut block = GenericArray::from([0u8; 8]);
        block.copy_from_slice(&plaintext[0..8]);
        let original = block.clone();

        cipher.encrypt_block(&mut block);
        assert_ne!(block, original);

        cipher.decrypt_block(&mut block);
        assert_eq!(block, original);
    }

    #[test]
    #[cfg(feature = "simd")]
    fn test_xtea_simd_consistency() {
        use cipher::BlockEncrypt;

        let key = GenericArray::from([0x42u8; 16]);
        let cipher = crate::xtea::Xtea::new(&key);

        let mut blocks_scalar = vec![GenericArray::from([0u8; 8]); 128];
        for (i, block) in blocks_scalar.iter_mut().enumerate() {
            block[0] = i as u8;
        }
        let mut blocks_simd = blocks_scalar.clone();

        // Encrypt scalar
        for block in &mut blocks_scalar {
            cipher.encrypt_block(block);
        }

        // Encrypt SIMD
        cipher.encrypt_blocks(&mut blocks_simd);

        assert_eq!(blocks_scalar, blocks_simd);
    }

    #[test]
    fn test_xtea_cbc_ecb_modes() {
        use crate::xtea::modes::{XteaCbc, XteaEcb};
        use cipher::generic_array::GenericArray;
        use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};

        let key = GenericArray::from([0u8; 16]);
        let iv = GenericArray::from([0u8; 8]);

        // CBC test: encrypt and then decrypt by manual block processing
        let plaintext = b"Hello, CBC World! Needs padding.";
        let mut padded = plaintext.to_vec();
        while padded.len() % 8 != 0 {
            padded.push(0);
        }

        let mut enc = XteaCbc::new(&key, &iv);
        let mut ciphertext = padded.clone();
        for block in ciphertext.chunks_mut(8) {
            let block = GenericArray::from_mut_slice(block);
            enc.encrypt_block_mut(block);
        }
        assert_ne!(ciphertext, padded);

        // Decrypt with the Decryptor type
        let mut dec = crate::xtea::modes::XteaCbcDec::new(&key, &iv);
        let mut decrypted = ciphertext.clone();
        for block in decrypted.chunks_mut(8) {
            let block = GenericArray::from_mut_slice(block);
            dec.decrypt_block_mut(block);
        }
        assert_eq!(decrypted, padded);

        // ECB test: encrypt two identical blocks and they should match
        let mut ecb_enc = XteaEcb::new(&key);
        let block = GenericArray::from([1u8; 8]);
        let mut flat = vec![];
        flat.extend_from_slice(&block);
        flat.extend_from_slice(&block);
        for b in flat.chunks_mut(8) {
            let b = GenericArray::from_mut_slice(b);
            ecb_enc.encrypt_block_mut(b);
        }
        let (b1, b2) = flat.split_at(8);
        assert_eq!(b1, b2);
    }
}

#[cfg(test)]
mod blowfish_tests {
    use crate::blowfish::Blowfish;
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    #[test]
    fn test_blowfish_basic_roundtrip() {
        let key = GenericArray::from([
            0x80, 0x6d, 0x79, 0x16, 0x23, 0x42, 0xa1, 0x0e, 0x8f, 0x78, 0x14, 0xd4, 0xf9, 0x94,
            0xa2, 0xd1, 0x74, 0x13, 0xfc, 0xa8, 0xf6, 0xe0, 0xb8, 0xa4, 0xed, 0xb9, 0xdc, 0x32,
            0x7f, 0x8b, 0xa7, 0x11,
        ]); // User provided key
        let cipher = Blowfish::new(&key);

        let original_block = GenericArray::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let mut block = original_block.clone();

        cipher.encrypt_block(&mut block);
        assert_ne!(block, original_block);

        cipher.decrypt_block(&mut block);
        assert_eq!(block, original_block);
    }

    #[test]
    fn test_blowfish_empty_key_roundtrip() {
        // RustCrypto KeyInit for Blowfish in my impl requires 32 bytes (U32).
        let key = GenericArray::from([0u8; 32]);
        let cipher = Blowfish::new(&key);

        let mut block = GenericArray::from([0u8; 8]);
        cipher.encrypt_block(&mut block);
        assert_ne!(block, GenericArray::from([0u8; 8]));

        cipher.decrypt_block(&mut block);
        assert_eq!(block, GenericArray::from([0u8; 8]));
    }

    // #[test]
    // fn iv_recovery_exploit() {
    //     use cipher::KeyInit;
    //     use std::io::Read;

    //     let key = GenericArray::from([
    //         0x80, 0x6d, 0x79, 0x16, 0x23, 0x42, 0xa1, 0x0e, 0x8f, 0x78, 0x14, 0xd4, 0xf9, 0x94,
    //         0xa2, 0xd1, 0x74, 0x13, 0xfc, 0xa8, 0xf6, 0xe0, 0xb8, 0xa4, 0xed, 0xb9, 0xdc, 0x32,
    //         0x7f, 0x8b, 0xa7, 0x11,
    //     ]);

    //     pub const fn normal_xor_8_bytes(a: [u8; 8], b: [u8; 8]) -> [u8; 8] {
    //         let bytes_a = i64::from_ne_bytes(a);
    //         let bytes_b = i64::from_ne_bytes(b);

    //         (bytes_a ^ bytes_b).to_ne_bytes()
    //     }

    //     // Load file from `SceneList.xml`
    //     let mut file = std::fs::File::open("SceneList.xml").unwrap();
    //     let mut buffer = Vec::new();
    //     file.read_to_end(&mut buffer).unwrap();

    //     // 1. Recover IV
    //     // Known plaintext header: "<?xml ve"
    //     let known_header = b"<?xml ve";
    //     let encrypted_header_bytes: [u8; 8] = buffer[0..8].try_into().unwrap();
    //     println!("Encrypted Header: {:x?}", encrypted_header_bytes);

    //     // Keystream block = P ^ C
    //     // P = K ^ C => K = P ^ C
    //     let keystream_block = normal_xor_8_bytes(encrypted_header_bytes, *known_header);
    //     println!(
    //         "Recovered Keystream Block (keystream): {:x?}",
    //         keystream_block
    //     );

    //     // The keystream block equals E_k(nonce). To recover the nonce (initial counter
    //     // block) we must decrypt the keystream block with Blowfish using the same key.
    //     let mut recovered_iv = GenericArray::from(keystream_block);
    //     let bf = Blowfish::new(&key);
    //     bf.decrypt_block(&mut recovered_iv);
    //     println!("Recovered Nonce (IV): {:x?}", recovered_iv);

    //     // Attempt to decrypt with BE counter first, then LE as fallback.
    //     let mut buffer_try = buffer.clone();
    //     let mut cipher_be = ctr::Ctr64BE::<Blowfish>::new(&key, &recovered_iv);
    //     cipher_be.apply_keystream(&mut buffer_try);
    //     println!(
    //         "Decrypted Start (BE): {:?}",
    //         String::from_utf8_lossy(&buffer_try[0..100])
    //     );

    //     if !buffer_try.starts_with(b"<?xml") {
    //         let mut buffer_try2 = buffer.clone();
    //         let mut cipher_le = ctr::Ctr64LE::<Blowfish>::new(&key, &recovered_iv);
    //         cipher_le.apply_keystream(&mut buffer_try2);
    //         println!(
    //             "Decrypted Start (LE): {:?}",
    //             String::from_utf8_lossy(&buffer_try2[0..100])
    //         );
    //         assert!(buffer_try2.starts_with(b"<?xml"));
    //         std::fs::write("decrypted_scene_list.xml", buffer_try2.as_slice()).unwrap();
    //     } else {
    //         assert!(buffer_try.starts_with(b"<?xml"));
    //         std::fs::write("decrypted_scene_list.xml", buffer_try.as_slice()).unwrap();
    //     }
    // }

    // #[test]
    // fn encryption() {
    //     // Read the decrypted file and re-encrypt it to verify correctness
    //     let key = GenericArray::from([
    //         0x80, 0x6d, 0x79, 0x16, 0x23, 0x42, 0xa1, 0x0e, 0x8f, 0x78, 0x14, 0xd4, 0xf9, 0x94,
    //         0xa2, 0xd1, 0x74, 0x13, 0xfc, 0xa8, 0xf6, 0xe0, 0xb8, 0xa4, 0xed, 0xb9, 0xdc, 0x32,
    //         0x7f, 0x8b, 0xa7, 0x11,
    //     ]);

    //     let mut file = std::fs::File::open("decrypted_scene_list.xml").unwrap();
    //     let mut buffer = Vec::new();
    //     file.read_to_end(&mut buffer).unwrap();

    //     // Get the first 8 bytes of the SHA-1 as IV
    //     // For now we can hardcode it: 9b4495714b5a7c42ad19af97853c5165d5a1a542
    //     let iv = GenericArray::from([0x9b, 0x44, 0x95, 0x71, 0x4b, 0x5a, 0x7c, 0x42]);

    //     let mut cipher = ctr::Ctr64BE::<Blowfish>::new(&key, &iv);
    //     cipher.apply_keystream(&mut buffer);

    //     // Read `SceneList.xml` for comparison
    //     let mut original_file = std::fs::File::open("SceneList.xml").unwrap();
    //     let mut original_buffer = Vec::new();
    //     original_file.read_to_end(&mut original_buffer).unwrap();

    //     assert_eq!(buffer, original_buffer);
    // }

    #[test]
    fn test_blowfish_cbc_mode() {
        use crate::modes::BlowfishCbc;
        use cipher::generic_array::GenericArray;
        use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

        let key = GenericArray::from([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
            0x2c, 0x2d, 0x2e, 0x2f,
        ]);
        let iv = GenericArray::from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]);

        let plaintext = b"Hello, CBC World! This needs to be padded...";
        // Manual padding to multiple of 8
        let mut padded = plaintext.to_vec();
        while padded.len() % 8 != 0 {
            padded.push(0);
        }

        // Encryption
        let mut cipher_enc = BlowfishCbc::new(&key, &iv);
        let mut ciphertext = padded.clone();
        for block in ciphertext.chunks_mut(8) {
            let block = GenericArray::from_mut_slice(block);
            cipher_enc.encrypt_block_mut(block);
        }

        assert_ne!(ciphertext, padded);

        // Decryption
        let mut cipher_dec = crate::modes::BlowfishCbcDec::new(&key, &iv);
        let mut decrypted = ciphertext.clone();
        for block in decrypted.chunks_mut(8) {
            let block = GenericArray::from_mut_slice(block);
            cipher_dec.decrypt_block_mut(block);
        }

        assert_eq!(decrypted, padded);
    }

    #[test]
    fn test_blowfish_ctr_consistency() {
        use cipher::BlockEncrypt;
        use cipher::{KeyInit, KeyIvInit, StreamCipher};
        use ctr::{Ctr64BE, Ctr64LE};

        // Deterministic key/iv for reproducibility
        let key = GenericArray::from([0u8; 32]);
        let iv = GenericArray::from([0u8, 0, 0, 0, 0, 0, 0, 1]);
        let cipher = Blowfish::new(&key);

        // Manual keystream generation using big-endian counter increments
        fn manual_keystream_be(cipher: &Blowfish, iv: [u8; 8], blocks: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(blocks * 8);
            let base = u64::from_be_bytes(iv);
            for i in 0..blocks {
                let ctr = base.wrapping_add(i as u64);
                let block = GenericArray::from(ctr.to_be_bytes());
                // encrypt_block takes &mut GenericArray
                let mut to_encrypt = block.clone();
                cipher.encrypt_block(&mut to_encrypt);
                out.extend_from_slice(to_encrypt.as_slice());
            }
            out
        }

        // Manual keystream generation using little-endian counter increments
        fn manual_keystream_le(cipher: &Blowfish, iv: [u8; 8], blocks: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(blocks * 8);
            let base = u64::from_le_bytes(iv);
            for i in 0..blocks {
                let ctr = base.wrapping_add(i as u64);
                let block = GenericArray::from(ctr.to_le_bytes());
                let mut to_encrypt = block.clone();
                cipher.encrypt_block(&mut to_encrypt);
                out.extend_from_slice(to_encrypt.as_slice());
            }
            out
        }

        let blocks = 4;

        // CTR crate (BE)
        let mut ctr_be = Ctr64BE::<Blowfish>::new(&key, &iv);
        // Apply to two sequential single-block buffers to see if the counter advances
        let mut b1 = [0u8; 8];
        let mut b2 = [0u8; 8];
        ctr_be.apply_keystream(&mut b1);
        ctr_be.apply_keystream(&mut b2);
        println!("ctr_be first block={:x?}", b1);
        println!("ctr_be second block={:x?}", b2);
        let mut ks_be = vec![0u8; blocks * 8];
        // Use a fresh CTR instance for the multi-block output
        let mut ctr_be2 = Ctr64BE::<Blowfish>::new(&key, &iv);
        ctr_be2.apply_keystream(&mut ks_be);

        // CTR crate (LE)
        let mut ctr_le = Ctr64LE::<Blowfish>::new(&key, &iv);
        let mut ks_le = vec![0u8; blocks * 8];
        ctr_le.apply_keystream(&mut ks_le);

        let manual_be = manual_keystream_be(&cipher, iv.into(), blocks);
        let manual_le = manual_keystream_le(&cipher, iv.into(), blocks);

        let be_matches = ks_be == manual_be;
        let le_matches = ks_le == manual_le;

        println!("ks_be={:x?}", ks_be);
        println!("manual_be={:x?}", manual_be);
        println!("ks_le={:x?}", ks_le);
        println!("manual_le={:x?}", manual_le);

        assert!(
            be_matches || le_matches,
            "CTR crate keystream did not match either manual BE or LE implementations"
        );
    }

    #[test]
    fn test_blowfish_ecb_mode() {
        use crate::modes::BlowfishEcb;
        use cipher::generic_array::GenericArray;
        use cipher::{BlockEncryptMut, KeyInit};

        let key = GenericArray::from([0u8; 32]);
        let mut cipher_enc = BlowfishEcb::new(&key);

        let block = GenericArray::from([1u8; 8]);
        // Two identical blocks in ECB should produce identical ciphertext blocks

        let mut flat_buffer = vec![];
        flat_buffer.extend_from_slice(&block);
        flat_buffer.extend_from_slice(&block);

        for block in flat_buffer.chunks_mut(8) {
            let block = GenericArray::from_mut_slice(block);
            cipher_enc.encrypt_block_mut(block);
        }

        let (b1, b2) = flat_buffer.split_at(8);
        assert_eq!(b1, b2); // ECB property: same plaintext block -> same ciphertext block
    }

    #[test]
    fn test_xtea_ctr_consistency() {
        use cipher::BlockEncrypt;
        use cipher::{KeyInit, KeyIvInit, StreamCipher};
        use ctr::{Ctr64BE, Ctr64LE};

        let key = GenericArray::from([0u8; 16]);
        let iv = GenericArray::from([0u8, 0, 0, 0, 0, 0, 0, 1]);
        let cipher = crate::xtea::Xtea::new(&key);

        fn manual_keystream_be(cipher: &crate::xtea::Xtea, iv: [u8; 8], blocks: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(blocks * 8);
            let base = u64::from_be_bytes(iv);
            for i in 0..blocks {
                let ctr = base.wrapping_add(i as u64);
                let block = GenericArray::from(ctr.to_be_bytes());
                let mut to_encrypt = block.clone();
                cipher.encrypt_block(&mut to_encrypt);
                out.extend_from_slice(to_encrypt.as_slice());
            }
            out
        }

        fn manual_keystream_le(cipher: &crate::xtea::Xtea, iv: [u8; 8], blocks: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(blocks * 8);
            let base = u64::from_le_bytes(iv);
            for i in 0..blocks {
                let ctr = base.wrapping_add(i as u64);
                let block = GenericArray::from(ctr.to_le_bytes());
                let mut to_encrypt = block.clone();
                cipher.encrypt_block(&mut to_encrypt);
                out.extend_from_slice(to_encrypt.as_slice());
            }
            out
        }

        let blocks = 4;

        let mut ctr_be = Ctr64BE::<crate::xtea::Xtea>::new(&key, &iv);
        let mut b1 = [0u8; 8];
        let mut b2 = [0u8; 8];
        ctr_be.apply_keystream(&mut b1);
        ctr_be.apply_keystream(&mut b2);

        let mut ctr_be2 = Ctr64BE::<crate::xtea::Xtea>::new(&key, &iv);
        let mut ks_be = vec![0u8; blocks * 8];
        ctr_be2.apply_keystream(&mut ks_be);

        let mut ctr_le = Ctr64LE::<crate::xtea::Xtea>::new(&key, &iv);
        let mut ks_le = vec![0u8; blocks * 8];
        ctr_le.apply_keystream(&mut ks_le);

        let manual_be = manual_keystream_be(&cipher, iv.into(), blocks);
        let manual_le = manual_keystream_le(&cipher, iv.into(), blocks);

        assert!(
            ks_be == manual_be || ks_le == manual_le,
            "CTR did not match manual BE or LE"
        );
    }

    #[test]
    fn crypto_writer_roundtrip() {
        use crate::blowfish::Blowfish;
        use crate::reader::CryptoReader;
        use crate::writer::CryptoWriter;
        use cipher::generic_array::GenericArray;
        use ctr::Ctr64BE;
        use ctr::cipher::KeyIvInit;
        use std::io::{Read, Write};

        // Deterministic key/iv for test
        let key = GenericArray::from([0x11u8; 32]);
        let iv = GenericArray::from([0x22u8; 8]);

        let plaintext = b"The quick brown fox jumps over the lazy dog".to_vec();

        // Encrypt via CryptoWriter
        let buf = Vec::new();
        let mut writer = CryptoWriter::new(buf, Ctr64BE::<Blowfish>::new(&key, &iv));
        writer.write_all(&plaintext).unwrap();
        writer.flush().unwrap();
        let buf = writer.into_inner();

        // Decrypt via CryptoReader
        let cursor = std::io::Cursor::new(buf);
        let mut reader = CryptoReader::new(cursor, Ctr64BE::<Blowfish>::new(&key, &iv));
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();

        assert_eq!(out, plaintext);
    }

    #[test]
    fn crypto_writer_small_writes() {
        use crate::blowfish::Blowfish;
        use crate::reader::CryptoReader;
        use crate::writer::CryptoWriter;
        use cipher::generic_array::GenericArray;
        use ctr::Ctr64BE;
        use ctr::cipher::KeyIvInit;
        use std::io::{Read, Write};

        // Deterministic key/iv for test
        let key = GenericArray::from([0x33u8; 32]);
        let iv = GenericArray::from([0x44u8; 8]);

        let pieces: Vec<Vec<u8>> = (0..200)
            .map(|i| format!("line {:04}\n", i).into_bytes())
            .collect();
        let mut plaintext = Vec::new();
        for p in &pieces {
            plaintext.extend_from_slice(p);
        }

        // Write many small pieces
        let buf = Vec::new();
        let mut writer = CryptoWriter::new(buf, Ctr64BE::<Blowfish>::new(&key, &iv));
        for p in &pieces {
            writer.write_all(p).unwrap();
        }
        writer.flush().unwrap();
        let buf = writer.into_inner();

        // Decrypt and verify
        let cursor = std::io::Cursor::new(buf);
        let mut reader = CryptoReader::new(cursor, Ctr64BE::<Blowfish>::new(&key, &iv));
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();

        assert_eq!(out, plaintext);
    }

    #[test]
    fn crypto_writer_with_capacity() {
        use crate::blowfish::Blowfish;
        use crate::reader::CryptoReader;
        use crate::writer::CryptoWriter;
        use cipher::generic_array::GenericArray;
        use ctr::Ctr64BE;
        use ctr::cipher::KeyIvInit;
        use std::io::{Read, Write};

        let key = GenericArray::from([0x55u8; 32]);
        let iv = GenericArray::from([0x66u8; 8]);
        let plaintext = b"capacity test".to_vec();

        let mut writer =
            CryptoWriter::with_capacity(Vec::new(), Ctr64BE::<Blowfish>::new(&key, &iv), 64);
        writer.write_all(&plaintext).unwrap();
        writer.flush().unwrap();
        let buf = writer.into_inner();

        let cursor = std::io::Cursor::new(buf);
        let mut reader = CryptoReader::new(cursor, Ctr64BE::<Blowfish>::new(&key, &iv));
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();

        assert_eq!(out, plaintext);
    }
}
