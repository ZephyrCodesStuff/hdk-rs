use cbc::cipher::{KeyIvInit, StreamCipher};

use crate::sce::crypto;
use crate::sce::errors::SceError;
use crate::sce::structs::{MetadataSectionHeader, SCE_HEADER_SIZE};
use std::io::{Read, Seek};

pub struct SceArchive<R: Read + Seek> {
    inner: R,
    header: crate::sce::structs::SCEHeader,
    meta_info: Option<crate::sce::structs::MetadataInfo>,
    meta_header: Option<crate::sce::structs::MetadataHeader>,
    section_headers: Vec<MetadataSectionHeader>,
    data_keys: Vec<u8>,
    file_size: u64,
}

impl<R: Read + Seek> SceArchive<R> {
    pub fn open(mut reader: R) -> Result<Self, SceError> {
        use std::io::SeekFrom;

        let file_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;

        let header =
            crate::sce::structs::SCEHeader::load_from_reader(&mut reader).map_err(SceError::Io)?;
        if !header.check_magic() {
            return Err(SceError::InvalidMagic);
        }

        Ok(SceArchive {
            inner: reader,
            header,
            meta_info: None,
            meta_header: None,
            section_headers: Vec::new(),
            data_keys: Vec::new(),
            file_size,
        })
    }

    pub fn header(&self) -> &crate::sce::structs::SCEHeader {
        &self.header
    }

    pub fn load_metadata(&mut self, erk: &[u8; 32], riv: &[u8; 16]) -> Result<(), SceError> {
        let sce_header = &self.header;

        let meta_info_start = (sce_header.se_meta as usize) + SCE_HEADER_SIZE;
        if meta_info_start + crate::sce::structs::SCE_METADATA_INFO_SIZE > (self.file_size as usize)
        {
            return Err(SceError::InvalidMetadata);
        }

        self.inner
            .seek(std::io::SeekFrom::Start(meta_info_start as u64))?;
        let mut meta_info_bytes = vec![0u8; crate::sce::structs::SCE_METADATA_INFO_SIZE];
        self.inner.read_exact(&mut meta_info_bytes)?;

        let metadata_headers_size = (sce_header.se_hsize as usize)
            .checked_sub(
                SCE_HEADER_SIZE
                    + sce_header.se_meta as usize
                    + crate::sce::structs::SCE_METADATA_INFO_SIZE,
            )
            .ok_or(SceError::InvalidMetadata)?;

        let headers_start = meta_info_start + crate::sce::structs::SCE_METADATA_INFO_SIZE;
        if headers_start + metadata_headers_size > (self.file_size as usize) {
            return Err(SceError::InvalidMetadata);
        }

        self.inner
            .seek(std::io::SeekFrom::Start(headers_start as u64))?;
        let mut metadata_headers = vec![0u8; metadata_headers_size];
        self.inner.read_exact(&mut metadata_headers)?;

        let mut metadata_key = [0u8; 32];
        let mut metadata_iv = [0u8; 16];
        metadata_key.copy_from_slice(erk);
        metadata_iv.copy_from_slice(riv);

        if (sce_header.se_flags & 0x8000) != 0x8000 {
            crypto::aes_decrypt_cbc(&metadata_key, &metadata_iv, &mut meta_info_bytes)
                .map_err(|_| SceError::InvalidMetadata)?;
        }

        let meta_info = crate::sce::structs::MetadataInfo::load_from_bytes(&meta_info_bytes);

        crypto::aes_decrypt_ctr(&meta_info.key, &meta_info.iv, &mut metadata_headers)
            .map_err(|_| SceError::InvalidMetadata)?;

        let meta_header = crate::sce::structs::MetadataHeader::load_from_bytes(&metadata_headers)
            .map_err(SceError::Io)?;

        let mut section_headers = Vec::new();
        let mut offset = SCE_HEADER_SIZE;

        for _ in 0..meta_header.section_count {
            if offset + crate::sce::structs::SCE_METADATA_SECTION_HEADER_SIZE
                > metadata_headers.len()
            {
                return Err(SceError::InvalidMetadata);
            }
            let section_header = crate::sce::structs::MetadataSectionHeader::load_from_bytes(
                &metadata_headers
                    [offset..offset + crate::sce::structs::SCE_METADATA_SECTION_HEADER_SIZE],
            )
            .map_err(SceError::Io)?;
            section_headers.push(section_header);
            offset += crate::sce::structs::SCE_METADATA_SECTION_HEADER_SIZE;
        }

        let data_keys_length = meta_header.key_count as usize * 16;
        let keys_start = offset;
        if keys_start + data_keys_length > metadata_headers.len() {
            return Err(SceError::InvalidMetadata);
        }

        let data_keys = metadata_headers[keys_start..keys_start + data_keys_length].to_vec();

        self.meta_info = Some(meta_info);
        self.meta_header = Some(meta_header);
        self.section_headers = section_headers;
        self.data_keys = data_keys;

        Ok(())
    }

    pub fn sections_metadata(&self) -> &[MetadataSectionHeader] {
        &self.section_headers
    }

    pub fn section_metadata(&self, index: usize) -> Result<MetadataSectionHeader, SceError> {
        Ok(*self
            .section_headers
            .get(index)
            .ok_or(SceError::SectionIndex)?)
    }

    pub fn section_reader<'a>(&'a mut self, index: usize) -> Result<Box<dyn Read + 'a>, SceError> {
        use aes::Aes128;
        use ctr::Ctr64BE;
        use flate2::read::ZlibDecoder;

        let sh = *self
            .section_headers
            .get(index)
            .ok_or(SceError::SectionIndex)?;

        let start = sh.data_offset as u64;
        let end = sh
            .data_offset
            .checked_add(sh.data_size)
            .ok_or(SceError::SectionOutOfBounds)?;
        if end > self.file_size {
            return Err(SceError::SectionOutOfBounds);
        }

        self.inner.seek(std::io::SeekFrom::Start(start))?;
        let take = (&mut self.inner).take(sh.data_size as u64);

        let mut reader: Box<dyn Read + 'a> = if sh.encrypted == 3 {
            let key_idx = sh.key_idx as usize;
            let iv_idx = sh.iv_idx as usize;
            let key_offset = key_idx * 16;
            let iv_offset = iv_idx * 16;
            if key_offset + 16 > self.data_keys.len() || iv_offset + 16 > self.data_keys.len() {
                return Err(SceError::InvalidMetadata);
            }
            let mut key = [0u8; 16];
            let mut iv = [0u8; 16];
            key.copy_from_slice(&self.data_keys[key_offset..key_offset + 16]);
            iv.copy_from_slice(&self.data_keys[iv_offset..iv_offset + 16]);

            struct CtrReader<RR: Read> {
                inner: RR,
                cipher: Ctr64BE<Aes128>,
            }

            impl<RR: Read> Read for CtrReader<RR> {
                fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                    let n = self.inner.read(buf)?;
                    if n > 0 {
                        self.cipher.apply_keystream(&mut buf[..n]);
                    }
                    Ok(n)
                }
            }

            let cipher = Ctr64BE::<Aes128>::new((&key).into(), (&iv).into());
            Box::new(CtrReader {
                inner: take,
                cipher,
            }) as Box<dyn Read + 'a>
        } else {
            Box::new(take) as Box<dyn Read + 'a>
        };

        if sh.compressed == 2 {
            reader = Box::new(ZlibDecoder::new(reader));
        }

        Ok(reader)
    }

    pub fn read_section(&mut self, index: usize) -> Result<Vec<u8>, SceError> {
        let mut r = self.section_reader(index)?;
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).map_err(SceError::Io)?;
        Ok(buf)
    }
}
