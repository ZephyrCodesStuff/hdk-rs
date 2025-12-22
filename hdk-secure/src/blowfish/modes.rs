/// Blowfish in CBC mode with PKCS7 padding
pub type BlowfishCbcPkcs7 = cbc::Encryptor<crate::blowfish::Blowfish>;
pub type BlowfishCbcDecPkcs7 = cbc::Decryptor<crate::blowfish::Blowfish>;

/// Blowfish in ECB mode with PKCS7 padding
pub type BlowfishEcbPkcs7 = ecb::Encryptor<crate::blowfish::Blowfish>;
pub type BlowfishEcbDecPkcs7 = ecb::Decryptor<crate::blowfish::Blowfish>;

// Raw modes (NoPadding) if needed for custom padding or raw block manipulation
pub type BlowfishCbc = cbc::Encryptor<crate::blowfish::Blowfish>;
pub type BlowfishCbcDec = cbc::Decryptor<crate::blowfish::Blowfish>;

pub type BlowfishEcb = ecb::Encryptor<crate::blowfish::Blowfish>;
pub type BlowfishEcbDec = ecb::Decryptor<crate::blowfish::Blowfish>;

// Type alias for the Blowfish CTR mode used for PS3 files
pub type BlowfishPS3 = ctr::Ctr64BE<crate::blowfish::Blowfish>;
