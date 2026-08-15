use byteorder::{ByteOrder, LittleEndian};
use cipher::{
    KeyInit, KeySizeUser,
    consts::U16,
    generic_array::GenericArray,
};

/// XXTEA golden ratio constant (DELTA)
pub const DELTA: u32 = 0x9E3779B9;

/// PlayStation Home Profanity Dictionary 128-bit key
pub const PROFANITY_DICT_KEY: [u32; 4] = [0xF512A417, 0x485EF87A, 0xB3D85E90, 0xC4923F75];

/// XXTEA (Corrected Block TEA) cipher.
///
/// XXTEA is a variable-length block cipher operating on slices of at least two 32-bit words ($n \ge 2$).
#[derive(Clone, Debug)]
pub struct Xxtea {
    key: [u32; 4],
}

impl KeySizeUser for Xxtea {
    type KeySize = U16;
}

impl KeyInit for Xxtea {
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let mut k = [0u32; 4];
        for (i, chunk) in key.as_chunks::<4>().0.iter().enumerate() {
            k[i] = LittleEndian::read_u32(chunk);
        }
        Self { key: k }
    }
}

impl Xxtea {
    /// Create a new `Xxtea` instance directly from four 32-bit key words.
    pub const fn new_from_words(key: [u32; 4]) -> Self {
        Self { key }
    }

    /// Return the key words.
    pub const fn key(&self) -> &[u32; 4] {
        &self.key
    }

    /// Encrypt a slice of 32-bit words in place.
    ///
    /// Slices with fewer than 2 elements are returned unchanged.
    pub fn encrypt(&self, v: &mut [u32]) {
        encrypt_words(v, &self.key);
    }

    /// Decrypt a slice of 32-bit words in place.
    ///
    /// Slices with fewer than 2 elements are returned unchanged.
    pub fn decrypt(&self, v: &mut [u32]) {
        decrypt_words(v, &self.key);
    }

    /// Decrypt a byte slice in place (must be a multiple of 4 bytes with length >= 8).
    pub fn decrypt_bytes(&self, data: &mut [u8]) -> Result<(), &'static str> {
        if data.len() < 8 || !data.len().is_multiple_of(4) {
            return Err("Data length must be a multiple of 4 bytes and at least 8 bytes");
        }
        let num_words = data.len() / 4;
        let mut words = vec![0u32; num_words];
        for (i, chunk) in data.as_chunks::<4>().0.iter().enumerate() {
            words[i] = LittleEndian::read_u32(chunk);
        }
        self.decrypt(&mut words);
        for (i, &w) in words.iter().enumerate() {
            LittleEndian::write_u32(&mut data[i * 4..(i + 1) * 4], w);
        }
        Ok(())
    }

    /// Encrypt a byte slice in place (must be a multiple of 4 bytes with length >= 8).
    pub fn encrypt_bytes(&self, data: &mut [u8]) -> Result<(), &'static str> {
        if data.len() < 8 || !data.len().is_multiple_of(4) {
            return Err("Data length must be a multiple of 4 bytes and at least 8 bytes");
        }
        let num_words = data.len() / 4;
        let mut words = vec![0u32; num_words];
        for (i, chunk) in data.as_chunks::<4>().0.iter().enumerate() {
            words[i] = LittleEndian::read_u32(chunk);
        }
        self.encrypt(&mut words);
        for (i, &w) in words.iter().enumerate() {
            LittleEndian::write_u32(&mut data[i * 4..(i + 1) * 4], w);
        }
        Ok(())
    }

    /// Decrypt PlayStation 3 big-endian word streams in place:
    /// performs XXTEA decryption followed by 32-bit word endian swap matching `PF_DeCipher` + `PF_SwapEndian`.
    pub fn decrypt_ps3_words(&self, v: &mut [u32]) {
        self.decrypt(v);
        for word in v.iter_mut() {
            *word = word.swap_bytes();
        }
    }

    /// Encrypt PlayStation 3 big-endian word streams in place:
    /// performs 32-bit word endian swap followed by XXTEA encryption.
    pub fn encrypt_ps3_words(&self, v: &mut [u32]) {
        for word in v.iter_mut() {
            *word = word.swap_bytes();
        }
        self.encrypt(v);
    }
}

/// Core XXTEA encryption algorithm on 32-bit words.
pub fn encrypt_words(v: &mut [u32], key: &[u32; 4]) {
    let n = v.len();
    if n < 2 {
        return;
    }

    let rounds = 6 + 52 / n;
    let mut total = 0u32;
    let mut z = v[n - 1];

    for _ in 0..rounds {
        total = total.wrapping_add(DELTA);
        let e = ((total >> 2) & 3) as usize;

        for p in 0..(n - 1) {
            let y = v[p + 1];
            let mx = ((z >> 5 ^ y.wrapping_shl(2)).wrapping_add((y >> 3) ^ z.wrapping_shl(4)))
                ^ (total ^ y).wrapping_add(key[(p & 3) ^ e] ^ z);
            v[p] = v[p].wrapping_add(mx);
            z = v[p];
        }

        let y = v[0];
        let mx = ((z >> 5 ^ y.wrapping_shl(2)).wrapping_add((y >> 3) ^ z.wrapping_shl(4)))
            ^ (total ^ y).wrapping_add(key[((n - 1) & 3) ^ e] ^ z);
        v[n - 1] = v[n - 1].wrapping_add(mx);
        z = v[n - 1];
    }
}

/// Core XXTEA decryption algorithm on 32-bit words.
pub fn decrypt_words(v: &mut [u32], key: &[u32; 4]) {
    let n = v.len();
    if n < 2 {
        return;
    }

    let rounds = 6 + 52 / n;
    let mut total = (rounds as u32).wrapping_mul(DELTA);
    let mut y = v[0];

    for _ in 0..rounds {
        let e = ((total >> 2) & 3) as usize;

        for p in (1..n).rev() {
            let z = v[p - 1];
            let mx = ((z >> 5 ^ y.wrapping_shl(2)).wrapping_add((y >> 3) ^ z.wrapping_shl(4)))
                ^ (total ^ y).wrapping_add(key[(p & 3) ^ e] ^ z);
            v[p] = v[p].wrapping_sub(mx);
            y = v[p];
        }

        let z = v[n - 1];
        let mx = ((z >> 5 ^ y.wrapping_shl(2)).wrapping_add((y >> 3) ^ z.wrapping_shl(4)))
            ^ (total ^ y).wrapping_add(key[e] ^ z);
        v[0] = v[0].wrapping_sub(mx);
        y = v[0];

        total = total.wrapping_sub(DELTA);
    }
}
