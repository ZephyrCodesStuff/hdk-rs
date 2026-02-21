use std::io;

use cbc::cipher::{KeyIvInit, StreamCipher};
use elliptic_curve::PrimeField;

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

/// Compute SHA-1 hash of data
pub fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1_smol::Sha1;
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.digest().bytes()
}

/// ECDSA curve types used in SCE files
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurve {
    /// VSH curve (used for most SCE files)
    Vsh,
}

/// ECDSA key pair for signing SCE files
#[derive(Debug, Clone)]
pub struct EcdsaKeypair {
    /// Private key (24 bytes for P-192)
    pub private_key: [u8; 24],
    /// Public key X coordinate (24 bytes)
    pub public_x: [u8; 24],
    /// Public key Y coordinate (24 bytes)
    pub public_y: [u8; 24],
}

impl EcdsaKeypair {
    /// Create a new keypair from raw bytes
    #[must_use]
    pub const fn new(private_key: [u8; 24], public_x: [u8; 24], public_y: [u8; 24]) -> Self {
        Self {
            private_key,
            public_x,
            public_y,
        }
    }

    /// Create a keypair from combined public key bytes (48 bytes: X || Y)
    #[must_use]
    pub fn from_private_and_public(private_key: [u8; 24], public_key: &[u8; 48]) -> Self {
        let mut public_x = [0u8; 24];
        let mut public_y = [0u8; 24];
        public_x.copy_from_slice(&public_key[0..24]);
        public_y.copy_from_slice(&public_key[24..48]);
        Self {
            private_key,
            public_x,
            public_y,
        }
    }
}

/// Sign data with ECDSA-P192-SHA1 and return (r, s) as 21-byte arrays
///
/// The signature format matches the SCE signature structure:
/// - R: 21 bytes (big-endian, zero-padded)
/// - S: 21 bytes (big-endian, zero-padded)
///
/// This is a manual implementation since the ecdsa crate does not implement
/// signing for P-192 due to its weak security (96-bit).
///
/// **Note**: This uses NIST P-192 which has 24-byte scalars. When values exceed
/// 168 bits (21 bytes), the top 3 bytes are truncated. For full compatibility
/// with PS3 SCE files, the actual PS3 curve parameters would be needed.
pub fn ecdsa_sign(keypair: &EcdsaKeypair, data: &[u8]) -> io::Result<([u8; 21], [u8; 21])> {
    let (r_full, s_full) = ecdsa_sign_full(keypair, data)?;
    
    // Truncate to 21 bytes for SCE format
    let mut r = [0u8; 21];
    let mut s = [0u8; 21];
    r.copy_from_slice(&r_full[3..]);
    s.copy_from_slice(&s_full[3..]);
    
    Ok((r, s))
}

/// Sign data with ECDSA-P192-SHA1 and return (r, s) as full 24-byte arrays.
/// This preserves all bits and allows correct round-trip verification with P-192.
pub fn ecdsa_sign_full(keypair: &EcdsaKeypair, data: &[u8]) -> io::Result<([u8; 24], [u8; 24])> {
    use crypto_bigint::U192;
    use elliptic_curve::Group;
    use elliptic_curve::ops::Reduce;
    use elliptic_curve::scalar::IsHigh;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p192::{ProjectivePoint, Scalar};

    // Hash the data with SHA-1 (20 bytes)
    let hash = sha1(data);

    // Convert hash to scalar (truncate/reduce to curve order)
    // SHA-1 is 160 bits, P-192 scalar is 192 bits, so we pad the hash
    let mut hash_padded = [0u8; 24];
    hash_padded[4..].copy_from_slice(&hash); // Left-pad with zeros
    let z = <Scalar as Reduce<U192>>::reduce_bytes(&hash_padded.into());

    // Parse private key as scalar
    let d = Scalar::from_repr(keypair.private_key.into());
    if d.is_none().into() {
        return Err(io::Error::other("invalid private key"));
    }
    let d = d.unwrap();

    // Generate random k (nonce) - use a deterministic approach based on RFC 6979
    // For simplicity, we'll use a hash-based deterministic nonce
    let k = generate_rfc6979_k(&keypair.private_key, &hash)?;

    // Compute R = k * G
    let r_point = ProjectivePoint::generator() * k;
    let r_affine = r_point.to_affine();
    let r_encoded = r_affine.to_encoded_point(false);
    let r_x_bytes = r_encoded
        .x()
        .ok_or_else(|| io::Error::other("point at infinity"))?;

    // r = x coordinate of R mod n
    let r_scalar = <Scalar as Reduce<U192>>::reduce_bytes(r_x_bytes);
    if r_scalar.is_zero().into() {
        return Err(io::Error::other("r is zero, retry with different k"));
    }

    // s = k^(-1) * (z + r * d) mod n
    let k_inv = k.invert();
    if k_inv.is_none().into() {
        return Err(io::Error::other("k has no inverse"));
    }
    let k_inv = k_inv.unwrap();

    let s_scalar = k_inv * (z + r_scalar * d);
    if s_scalar.is_zero().into() {
        return Err(io::Error::other("s is zero, retry with different k"));
    }

    // Normalize s to low-S form (s = min(s, n - s)) for BIP-62 / malleability fix
    let s_scalar = if s_scalar.is_high().into() {
        -s_scalar
    } else {
        s_scalar
    };

    // Convert to bytes
    let r_bytes: [u8; 24] = r_scalar.to_repr().into();
    let s_bytes: [u8; 24] = s_scalar.to_repr().into();

    Ok((r_bytes, s_bytes))
}

/// Generate deterministic k using RFC 6979 (simplified version)
fn generate_rfc6979_k(private_key: &[u8; 24], hash: &[u8; 20]) -> io::Result<p192::Scalar> {
    use crypto_bigint::U192;
    use elliptic_curve::ops::Reduce;
    use p192::Scalar;

    // Simplified RFC 6979: HMAC-SHA1 based deterministic nonce
    // V = 0x01 repeated, K = 0x00 repeated
    // This is a simplified implementation - for production use a proper RFC 6979 lib

    let mut v = [0x01u8; 20];
    let mut k_hmac = [0x00u8; 20];

    // K = HMAC_K(V || 0x00 || private_key || hash)
    let mut data = Vec::with_capacity(20 + 1 + 24 + 20);
    data.extend_from_slice(&v);
    data.push(0x00);
    data.extend_from_slice(private_key);
    data.extend_from_slice(hash);
    k_hmac = hmac_sha1(&k_hmac, &data);

    // V = HMAC_K(V)
    v = hmac_sha1(&k_hmac, &v);

    // K = HMAC_K(V || 0x01 || private_key || hash)
    data.clear();
    data.extend_from_slice(&v);
    data.push(0x01);
    data.extend_from_slice(private_key);
    data.extend_from_slice(hash);
    k_hmac = hmac_sha1(&k_hmac, &data);

    // V = HMAC_K(V)
    v = hmac_sha1(&k_hmac, &v);

    // Generate candidate k values until we get a valid one
    for _ in 0..100 {
        // T = empty, then append HMAC results until we have enough bits
        let mut t = Vec::with_capacity(24);
        while t.len() < 24 {
            v = hmac_sha1(&k_hmac, &v);
            t.extend_from_slice(&v);
        }

        // Convert to scalar
        let mut k_bytes = [0u8; 24];
        k_bytes.copy_from_slice(&t[..24]);

        let k_candidate = <Scalar as Reduce<U192>>::reduce_bytes(&k_bytes.into());

        // Check if k is valid (not zero, not >= n)
        if !bool::from(k_candidate.is_zero()) {
            return Ok(k_candidate);
        }

        // K = HMAC_K(V || 0x00)
        let mut data2 = Vec::with_capacity(21);
        data2.extend_from_slice(&v);
        data2.push(0x00);
        k_hmac = hmac_sha1(&k_hmac, &data2);
        v = hmac_sha1(&k_hmac, &v);
    }

    Err(io::Error::other("failed to generate valid k"))
}

/// Simple HMAC-SHA1 implementation
fn hmac_sha1(key: &[u8; 20], data: &[u8]) -> [u8; 20] {
    use sha1_smol::Sha1;

    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Pad or hash the key to block size
    let mut k_padded = [0u8; BLOCK_SIZE];
    if key.len() <= BLOCK_SIZE {
        k_padded[..key.len()].copy_from_slice(key);
    } else {
        let mut hasher = Sha1::new();
        hasher.update(key);
        k_padded[..20].copy_from_slice(&hasher.digest().bytes());
    }

    // Inner hash: SHA1((K XOR ipad) || data)
    let mut inner_key = [0u8; BLOCK_SIZE];
    for (i, &b) in k_padded.iter().enumerate() {
        inner_key[i] = b ^ IPAD;
    }

    let mut inner_hasher = Sha1::new();
    inner_hasher.update(&inner_key);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.digest().bytes();

    // Outer hash: SHA1((K XOR opad) || inner_hash)
    let mut outer_key = [0u8; BLOCK_SIZE];
    for (i, &b) in k_padded.iter().enumerate() {
        outer_key[i] = b ^ OPAD;
    }

    let mut outer_hasher = Sha1::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    outer_hasher.digest().bytes()
}

/// Verify an ECDSA-P192-SHA1 signature
///
/// This is a manual implementation since the ecdsa crate does not implement
/// verification for P-192 due to its weak security (96-bit).
pub fn ecdsa_verify(
    keypair: &EcdsaKeypair,
    data: &[u8],
    r: &[u8; 21],
    s: &[u8; 21],
) -> io::Result<bool> {
    use crypto_bigint::U192;
    use elliptic_curve::ops::Reduce;
    use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use elliptic_curve::{AffinePoint, Group};
    use p192::{NistP192, ProjectivePoint, Scalar};

    // Hash the data with SHA-1
    let hash = sha1(data);

    // Convert hash to scalar
    let mut hash_padded = [0u8; 24];
    hash_padded[4..].copy_from_slice(&hash);
    let z = <Scalar as Reduce<U192>>::reduce_bytes(&hash_padded.into());

    // Parse r and s (pad from 21 bytes to 24 bytes)
    let mut r_padded = [0u8; 24];
    let mut s_padded = [0u8; 24];
    r_padded[3..].copy_from_slice(r);
    s_padded[3..].copy_from_slice(s);

    let r_scalar = Scalar::from_repr(r_padded.into());
    let s_scalar = Scalar::from_repr(s_padded.into());

    if r_scalar.is_none().into() || s_scalar.is_none().into() {
        return Ok(false);
    }
    let r_scalar = r_scalar.unwrap();
    let s_scalar = s_scalar.unwrap();

    // Check r, s are in valid range [1, n-1]
    if r_scalar.is_zero().into() || s_scalar.is_zero().into() {
        return Ok(false);
    }

    // Compute s^(-1)
    let s_inv = s_scalar.invert();
    if s_inv.is_none().into() {
        return Ok(false);
    }
    let s_inv = s_inv.unwrap();

    // u1 = z * s^(-1) mod n
    // u2 = r * s^(-1) mod n
    let u1 = z * s_inv;
    let u2 = r_scalar * s_inv;
    
    eprintln!("verify: z  = {:02x?}", <[u8; 24]>::from(z.to_repr()));
    eprintln!("verify: r  = {:02x?}", <[u8; 24]>::from(r_scalar.to_repr()));
    eprintln!("verify: s  = {:02x?}", <[u8; 24]>::from(s_scalar.to_repr()));
    eprintln!("verify: u1 = {:02x?}", <[u8; 24]>::from(u1.to_repr()));
    eprintln!("verify: u2 = {:02x?}", <[u8; 24]>::from(u2.to_repr()));

    // Parse public key
    let mut pubkey_x = [0u8; 24];
    let mut pubkey_y = [0u8; 24];
    pubkey_x.copy_from_slice(&keypair.public_x);
    pubkey_y.copy_from_slice(&keypair.public_y);

    // Build the public key point
    let pubkey_point = {
        use elliptic_curve::sec1::EncodedPoint;
        let mut encoded = [0u8; 49];
        encoded[0] = 0x04; // Uncompressed
        encoded[1..25].copy_from_slice(&pubkey_x);
        encoded[25..49].copy_from_slice(&pubkey_y);

        let point = EncodedPoint::<NistP192>::from_bytes(encoded)
            .map_err(|_| io::Error::other("invalid public key encoding"))?;

        let affine = AffinePoint::<NistP192>::from_encoded_point(&point);
        if affine.is_none().into() {
            return Ok(false);
        }
        ProjectivePoint::from(affine.unwrap())
    };

    // R' = u1 * G + u2 * Q
    let r_prime = ProjectivePoint::generator() * u1 + pubkey_point * u2;

    // Check if R' is the point at infinity
    if r_prime.is_identity().into() {
        return Ok(false);
    }

    // Get x coordinate of R'
    let r_prime_affine = r_prime.to_affine();
    let r_prime_encoded = r_prime_affine.to_encoded_point(false);
    let r_prime_x = r_prime_encoded
        .x()
        .ok_or_else(|| io::Error::other("point at infinity"))?;

    // v = x coordinate of R' mod n
    let v = <Scalar as Reduce<U192>>::reduce_bytes(r_prime_x);

    eprintln!("verify: r_scalar = {:02x?}", <[u8; 24]>::from(r_scalar.to_repr()));
    eprintln!("verify: v        = {:02x?}", <[u8; 24]>::from(v.to_repr()));

    // Signature is valid if v == r
    Ok(v == r_scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a test keypair by deriving public key from private key
    fn generate_test_keypair() -> EcdsaKeypair {
        use elliptic_curve::Group;
        use elliptic_curve::sec1::ToEncodedPoint;
        use p192::{ProjectivePoint, Scalar};

        // Use a fixed test private key (NOT for production use!)
        let private_key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        // Derive public key: Q = d * G
        let d = Scalar::from_repr(private_key.into()).unwrap();
        let q = ProjectivePoint::generator() * d;
        let q_affine = q.to_affine();
        let q_encoded = q_affine.to_encoded_point(false);

        let mut public_x = [0u8; 24];
        let mut public_y = [0u8; 24];
        public_x.copy_from_slice(q_encoded.x().unwrap());
        public_y.copy_from_slice(q_encoded.y().unwrap());

        EcdsaKeypair::new(private_key, public_x, public_y)
    }

    #[test]
    fn ecdsa_sign_verify_roundtrip() {
        let keypair = generate_test_keypair();
        let data = b"Hello, SCE signing test!";

        // Sign the data
        let (r, s) = ecdsa_sign(&keypair, data).expect("signing should succeed");

        eprintln!("r = {:02x?}", r);
        eprintln!("s = {:02x?}", s);

        // Verify the signature
        let valid = ecdsa_verify(&keypair, data, &r, &s).expect("verification should succeed");
        assert!(valid, "signature should be valid");
    }

    #[test]
    fn ecdsa_verify_rejects_tampered_data() {
        let keypair = generate_test_keypair();
        let data = b"Original data";
        let tampered = b"Tampered data";

        // Sign the original data
        let (r, s) = ecdsa_sign(&keypair, data).expect("signing should succeed");

        // Verify with tampered data should fail
        let valid = ecdsa_verify(&keypair, tampered, &r, &s).expect("verification should succeed");
        assert!(!valid, "signature should be invalid for tampered data");
    }

    #[test]
    fn ecdsa_verify_rejects_tampered_signature() {
        let keypair = generate_test_keypair();
        let data = b"Test data for signature tampering";

        // Sign the data
        let (mut r, s) = ecdsa_sign(&keypair, data).expect("signing should succeed");

        // Tamper with the signature
        r[10] ^= 0xFF;

        // Verify should fail
        let valid = ecdsa_verify(&keypair, data, &r, &s).expect("verification should succeed");
        assert!(!valid, "signature should be invalid after tampering");
    }

    #[test]
    fn ecdsa_deterministic_signatures() {
        let keypair = generate_test_keypair();
        let data = b"Deterministic signature test";

        // Sign the same data twice
        let (r1, s1) = ecdsa_sign(&keypair, data).expect("first signing should succeed");
        let (r2, s2) = ecdsa_sign(&keypair, data).expect("second signing should succeed");

        // RFC 6979 should produce deterministic signatures
        assert_eq!(r1, r2, "r values should be deterministic");
        assert_eq!(s1, s2, "s values should be deterministic");
    }

    #[test]
    fn sha1_known_vector() {
        // Test vector: SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let result = sha1(b"abc");
        let expected: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(result, expected);
    }
}
