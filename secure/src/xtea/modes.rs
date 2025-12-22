/// XTEA mode type aliases similar to Blowfish modes
pub type XteaCbcPkcs7 = cbc::Encryptor<crate::xtea::Xtea>;
pub type XteaCbcDecPkcs7 = cbc::Decryptor<crate::xtea::Xtea>;

pub type XteaEcbPkcs7 = ecb::Encryptor<crate::xtea::Xtea>;
pub type XteaEcbDecPkcs7 = ecb::Decryptor<crate::xtea::Xtea>;

// Raw modes (NoPadding)
pub type XteaCbc = cbc::Encryptor<crate::xtea::Xtea>;
pub type XteaCbcDec = cbc::Decryptor<crate::xtea::Xtea>;

pub type XteaEcb = ecb::Encryptor<crate::xtea::Xtea>;
pub type XteaEcbDec = ecb::Decryptor<crate::xtea::Xtea>;
