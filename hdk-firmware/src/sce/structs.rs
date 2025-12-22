use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

pub const SCE_MAGIC: &[u8; 4] = b"SCE\0";
pub const SCE_HEADER_SIZE: usize = 32;
pub const SCE_METADATA_INFO_SIZE: usize = 64;
pub const SCE_METADATA_SECTION_HEADER_SIZE: usize = 48;

#[derive(Debug, Clone, Copy)]
pub struct SCEHeader {
    pub magic: u32,
    pub version: u32,
    pub se_flags: u16,
    pub se_type: u16,
    pub se_meta: u32,
    pub se_hsize: u64,
    pub se_esize: u64,
}

impl SCEHeader {
    pub fn load_from_reader<R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        let magic = reader.read_u32::<BigEndian>()?;
        let version = reader.read_u32::<BigEndian>()?;
        let se_flags = reader.read_u16::<BigEndian>()?;
        let se_type = reader.read_u16::<BigEndian>()?;
        let se_meta = reader.read_u32::<BigEndian>()?;
        let se_hsize = reader.read_u64::<BigEndian>()?;
        let se_esize = reader.read_u64::<BigEndian>()?;

        Ok(Self {
            magic,
            version,
            se_flags,
            se_type,
            se_meta,
            se_hsize,
            se_esize,
        })
    }

    #[must_use] 
    pub fn check_magic(&self) -> bool {
        &self.magic.to_be_bytes() == SCE_MAGIC
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetadataInfo {
    pub key: [u8; 16],
    pub key_pad: [u8; 16],
    pub iv: [u8; 16],
    pub iv_pad: [u8; 16],
}

impl MetadataInfo {
    #[must_use] 
    pub fn load_from_bytes(data: &[u8]) -> Self {
        let mut key = [0u8; 16];
        let mut key_pad = [0u8; 16];
        let mut iv = [0u8; 16];
        let mut iv_pad = [0u8; 16];

        key.copy_from_slice(&data[0..16]);
        key_pad.copy_from_slice(&data[16..32]);
        iv.copy_from_slice(&data[32..48]);
        iv_pad.copy_from_slice(&data[48..64]);

        Self {
            key,
            key_pad,
            iv,
            iv_pad,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetadataHeader {
    pub signature_input_length: u64,
    pub unknown1: u32,
    pub section_count: u32,
    pub key_count: u32,
    pub opt_header_size: u32,
    pub unknown2: u32,
    pub unknown3: u32,
}

impl MetadataHeader {
    pub fn load_from_bytes(data: &[u8]) -> Result<Self, std::io::Error> {
        let mut cursor = Cursor::new(data);
        let signature_input_length = cursor.read_u64::<BigEndian>()?;
        let unknown1 = cursor.read_u32::<BigEndian>()?;
        let section_count = cursor.read_u32::<BigEndian>()?;
        let key_count = cursor.read_u32::<BigEndian>()?;
        let opt_header_size = cursor.read_u32::<BigEndian>()?;
        let unknown2 = cursor.read_u32::<BigEndian>()?;
        let unknown3 = cursor.read_u32::<BigEndian>()?;

        Ok(Self {
            signature_input_length,
            unknown1,
            section_count,
            key_count,
            opt_header_size,
            unknown2,
            unknown3,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetadataSectionHeader {
    pub data_offset: u64,
    pub data_size: u64,
    pub data_type: u32,
    pub program_idx: u32,
    pub hashed: u32,
    pub sha1_idx: u32,
    pub encrypted: u32,
    pub key_idx: u32,
    pub iv_idx: u32,
    pub compressed: u32,
}

impl MetadataSectionHeader {
    pub fn load_from_bytes(data: &[u8]) -> Result<Self, std::io::Error> {
        let mut cursor = Cursor::new(data);
        let data_offset = cursor.read_u64::<BigEndian>()?;
        let data_size = cursor.read_u64::<BigEndian>()?;
        let data_type = cursor.read_u32::<BigEndian>()?;
        let program_idx = cursor.read_u32::<BigEndian>()?;
        let hashed = cursor.read_u32::<BigEndian>()?;
        let sha1_idx = cursor.read_u32::<BigEndian>()?;
        let encrypted = cursor.read_u32::<BigEndian>()?;
        let key_idx = cursor.read_u32::<BigEndian>()?;
        let iv_idx = cursor.read_u32::<BigEndian>()?;
        let compressed = cursor.read_u32::<BigEndian>()?;

        Ok(Self {
            data_offset,
            data_size,
            data_type,
            program_idx,
            hashed,
            sha1_idx,
            encrypted,
            key_idx,
            iv_idx,
            compressed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_info_parses_ok() {
        let mut b = [0u8; 64];
        b[0] = 1;
        b[16] = 0;
        b[32] = 2;
        b[48] = 0;
        let mi = MetadataInfo::load_from_bytes(&b);
        assert_eq!(mi.key[0], 1);
        assert_eq!(mi.key_pad[0], 0);
        assert_eq!(mi.iv[0], 2);
        assert_eq!(mi.iv_pad[0], 0);
    }

    #[test]
    fn meta_header_and_section_parsing() {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&123u64.to_be_bytes()); // signature_input_length
        hdr.extend_from_slice(&0xdeadbeefu32.to_be_bytes());
        hdr.extend_from_slice(&2u32.to_be_bytes()); // section_count
        hdr.extend_from_slice(&3u32.to_be_bytes()); // key_count
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&0u32.to_be_bytes());

        let mh = MetadataHeader::load_from_bytes(&hdr).expect("meta header parse");
        assert_eq!(mh.section_count, 2);
        assert_eq!(mh.key_count, 3);

        let mut sh = Vec::new();
        sh.extend_from_slice(&8u64.to_be_bytes());
        sh.extend_from_slice(&16u64.to_be_bytes());
        sh.extend_from_slice(&1u32.to_be_bytes());
        sh.extend_from_slice(&0u32.to_be_bytes());
        sh.extend_from_slice(&0u32.to_be_bytes());
        sh.extend_from_slice(&0u32.to_be_bytes());
        sh.extend_from_slice(&3u32.to_be_bytes()); // encrypted
        sh.extend_from_slice(&1u32.to_be_bytes());
        sh.extend_from_slice(&1u32.to_be_bytes());
        sh.extend_from_slice(&2u32.to_be_bytes());

        let msh = MetadataSectionHeader::load_from_bytes(&sh).expect("section parse");
        assert_eq!(msh.data_offset, 8);
        assert_eq!(msh.data_size, 16);
        assert_eq!(msh.encrypted, 3);
    }
}
