use std::io;

use cbc::cipher::{KeyIvInit, StreamCipher};

/// AES-CBC encrypt in-place. `data` must be a multiple of 16 bytes.
pub fn aes_encrypt_cbc(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> io::Result<()> {
    use aes::Aes256;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    let encryptor = Aes256CbcEnc::new(key.into(), iv.into());
    encryptor
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(data, data.len())
        .map_err(|_| io::Error::other("cbc encrypt failed"))?;

    Ok(())
}

/// AES-CTR decrypt in-place. `data` can be any length.
pub fn aes_decrypt_cbc(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> io::Result<()> {
    use aes::Aes256;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    type Aes256CbcDec = cbc::Decryptor<Aes256>;

    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(data)
        .map_err(|_| io::Error::other("cbc decrypt failed"))?;

    Ok(())
}

/// AES-CTR decrypt in-place (big-endian counter). `data` can be any length.
pub fn aes_decrypt_ctr(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> io::Result<()> {
    use aes::Aes128;
    use ctr::Ctr128BE;

    let mut cipher = Ctr128BE::<Aes128>::new(key.into(), iv.into());
    cipher.apply_keystream(data);
    Ok(())
}

/// AES-CTR decrypt in-place (little-endian counter). `data` can be any length.
pub fn aes_decrypt_ctr_le(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> io::Result<()> {
    use aes::Aes128;
    use ctr::Ctr128LE;

    let mut cipher = Ctr128LE::<Aes128>::new(key.into(), iv.into());
    cipher.apply_keystream(data);
    Ok(())
}

/// Helper function to zlib-decompress data.
pub fn zlib_decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}
