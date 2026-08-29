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

    /// Create a new `Xxtea` instance from raw key bytes using the specified endianness.
    pub fn new_with_endian<E: ByteOrder>(key: &GenericArray<u8, <Self as KeySizeUser>::KeySize>) -> Self {
        let mut k = [0u32; 4];
        for (i, chunk) in key.as_chunks::<4>().0.iter().enumerate() {
            k[i] = E::read_u32(chunk);
        }
        Self { key: k }
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

    /// Decrypt a byte slice in place using specified endianness (must be a multiple of 4 bytes with length >= 8).
    pub fn decrypt_bytes_with_endian<E: ByteOrder>(&self, data: &mut [u8]) -> Result<(), &'static str> {
        if data.len() < 8 || !data.len().is_multiple_of(4) {
            return Err("Data length must be a multiple of 4 bytes and at least 8 bytes");
        }
        decrypt_bytes_in_place::<E>(data, &self.key);
        Ok(())
    }

    /// Encrypt a byte slice in place using specified endianness (must be a multiple of 4 bytes with length >= 8).
    pub fn encrypt_bytes_with_endian<E: ByteOrder>(&self, data: &mut [u8]) -> Result<(), &'static str> {
        if data.len() < 8 || !data.len().is_multiple_of(4) {
            return Err("Data length must be a multiple of 4 bytes and at least 8 bytes");
        }
        encrypt_bytes_in_place::<E>(data, &self.key);
        Ok(())
    }

    /// Decrypt a byte slice in place (LittleEndian by default).
    pub fn decrypt_bytes(&self, data: &mut [u8]) -> Result<(), &'static str> {
        self.decrypt_bytes_with_endian::<LittleEndian>(data)
    }

    /// Encrypt a byte slice in place (LittleEndian by default).
    pub fn encrypt_bytes(&self, data: &mut [u8]) -> Result<(), &'static str> {
        self.encrypt_bytes_with_endian::<LittleEndian>(data)
    }

    /// Decrypt PlayStation 3 big-endian byte streams in place without allocations.
    pub fn decrypt_ps3_bytes(&self, data: &mut [u8]) -> Result<(), &'static str> {
        self.decrypt_bytes_with_endian::<byteorder::BigEndian>(data)
    }

    /// Encrypt PlayStation 3 big-endian byte streams in place without allocations.
    pub fn encrypt_ps3_bytes(&self, data: &mut [u8]) -> Result<(), &'static str> {
        self.encrypt_bytes_with_endian::<byteorder::BigEndian>(data)
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

#[inline(always)]
fn get_u32<E: ByteOrder>(data: &[u8], idx: usize) -> u32 {
    let off = idx * 4;
    E::read_u32(&data[off..off + 4])
}

#[inline(always)]
fn set_u32<E: ByteOrder>(data: &mut [u8], idx: usize, val: u32) {
    let off = idx * 4;
    E::write_u32(&mut data[off..off + 4], val);
}

/// In-place XXTEA encryption directly on a byte slice parameterized by endianness.
pub fn encrypt_bytes_in_place<E: ByteOrder>(data: &mut [u8], key: &[u32; 4]) {
    let n = data.len() / 4;
    if n < 2 {
        return;
    }

    let rounds = 6 + 52 / n;
    let mut total = 0u32;
    let mut z = get_u32::<E>(data, n - 1);

    for _ in 0..rounds {
        total = total.wrapping_add(DELTA);
        let e = ((total >> 2) & 3) as usize;

        for p in 0..(n - 1) {
            let y = get_u32::<E>(data, p + 1);
            let mx = ((z >> 5 ^ y.wrapping_shl(2)).wrapping_add((y >> 3) ^ z.wrapping_shl(4)))
                ^ (total ^ y).wrapping_add(key[(p & 3) ^ e] ^ z);
            let val = get_u32::<E>(data, p).wrapping_add(mx);
            set_u32::<E>(data, p, val);
            z = val;
        }

        let y = get_u32::<E>(data, 0);
        let mx = ((z >> 5 ^ y.wrapping_shl(2)).wrapping_add((y >> 3) ^ z.wrapping_shl(4)))
            ^ (total ^ y).wrapping_add(key[((n - 1) & 3) ^ e] ^ z);
        let val = get_u32::<E>(data, n - 1).wrapping_add(mx);
        set_u32::<E>(data, n - 1, val);
        z = val;
    }
}

/// In-place XXTEA decryption directly on a byte slice parameterized by endianness.
pub fn decrypt_bytes_in_place<E: ByteOrder>(data: &mut [u8], key: &[u32; 4]) {
    let n = data.len() / 4;
    if n < 2 {
        return;
    }

    let rounds = 6 + 52 / n;
    let mut total = (rounds as u32).wrapping_mul(DELTA);
    let mut y = get_u32::<E>(data, 0);

    for _ in 0..rounds {
        let e = ((total >> 2) & 3) as usize;

        for p in (1..n).rev() {
            let z = get_u32::<E>(data, p - 1);
            let mx = ((z >> 5 ^ y.wrapping_shl(2)).wrapping_add((y >> 3) ^ z.wrapping_shl(4)))
                ^ (total ^ y).wrapping_add(key[(p & 3) ^ e] ^ z);
            let val = get_u32::<E>(data, p).wrapping_sub(mx);
            set_u32::<E>(data, p, val);
            y = val;
        }

        let z = get_u32::<E>(data, n - 1);
        let mx = ((z >> 5 ^ y.wrapping_shl(2)).wrapping_add((y >> 3) ^ z.wrapping_shl(4)))
            ^ (total ^ y).wrapping_add(key[e] ^ z);
        let val = get_u32::<E>(data, 0).wrapping_sub(mx);
        set_u32::<E>(data, 0, val);
        y = val;

        total = total.wrapping_sub(DELTA);
    }
}


