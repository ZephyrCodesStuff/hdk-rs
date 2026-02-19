use std::io::{Read, Seek, SeekFrom, Write};

use crate::block::{BlockMetadata, DataBlockProcessor, METADATA_OFFSET};
use crate::crypto::SdatKeys;
use crate::error::SdatError;
use crate::headers::EdatFlag;
use crate::headers::{EdatHeader, NpdHeader};
use crate::options::DecryptBlockOptions;

/// High-level, streaming(ish) SDAT reader.
pub struct SdatReader<R: Read + Seek> {
    inner: R,
    npd_header: NpdHeader,
    edat_header: EdatHeader,
    crypt_key: [u8; 16],
    block_processor: DataBlockProcessor,
    block_num: usize,
    metadata_section_size: usize,
}

impl<R: Read + Seek> SdatReader<R> {
    /// Open an SDAT file from a seekable reader.
    ///
    /// # Arguments
    ///
    /// * `inner` - The seekable reader containing the SDAT file.
    /// * `keys` - The cryptographic keys required for decryption.
    pub fn open(mut inner: R, keys: &SdatKeys) -> Result<Self, SdatError> {
        inner
            .seek(SeekFrom::Start(0))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek: {e}")))?;

        let mut npd_buf = vec![0u8; NpdHeader::SIZE];
        inner
            .read_exact(&mut npd_buf)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to read NPD header: {e}")))?;

        let npd_header = NpdHeader::parse(&npd_buf)?;
        npd_header.validate()?;

        let mut edat_buf = vec![0u8; EdatHeader::SIZE];
        inner
            .read_exact(&mut edat_buf)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to read EDAT header: {e}")))?;
        let edat_header = EdatHeader::parse(&edat_buf)?;

        if !edat_header.is_sdat() {
            return Err(SdatError::InvalidFormat);
        }

        let crypt_key = crate::crypto::generate_sdat_key(&keys.sdat_key, &npd_header.dev_hash);

        let block_num = edat_header
            .file_size
            .div_ceil(u64::from(edat_header.block_size)) as usize;

        let metadata_section_size = if edat_header.flags_bits().contains(EdatFlag::Compressed)
            || edat_header.flags_bits().contains(EdatFlag::Flag0x20)
        {
            0x20
        } else {
            0x10
        };

        Ok(Self {
            inner,
            npd_header,
            edat_header,
            crypt_key,
            block_processor: DataBlockProcessor::new(*keys),
            block_num,
            metadata_section_size,
        })
    }

    pub const fn npd_header(&self) -> &NpdHeader {
        &self.npd_header
    }

    pub const fn edat_header(&self) -> &EdatHeader {
        &self.edat_header
    }

    pub const fn file_size(&self) -> u64 {
        self.edat_header.file_size
    }

    pub const fn block_size(&self) -> u32 {
        self.edat_header.block_size
    }

    pub const fn block_count(&self) -> usize {
        self.block_num
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), SdatError> {
        self.inner
            .seek(SeekFrom::Start(offset))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek: {e}")))?;
        self.inner
            .read_exact(buf)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to read at {offset:#X}: {e}")))
    }

    fn block_metadata(&mut self, block_index: usize) -> Result<BlockMetadata, SdatError> {
        if block_index >= self.block_num {
            return Err(SdatError::InvalidHeader(
                "Block index out of range".to_string(),
            ));
        }

        let metadata_offset = METADATA_OFFSET as u64;

        if self.edat_header.flags_bits().contains(EdatFlag::Compressed) {
            // 0x20 bytes per block
            let entry_off =
                metadata_offset + (block_index as u64) * (self.metadata_section_size as u64);
            let mut meta = [0u8; 0x20];
            self.read_exact_at(entry_off, &mut meta)?;

            let (offset, length, compression_end) = if self.npd_header.version <= 1 {
                let offset = u64::from_be_bytes([
                    meta[0x10], meta[0x11], meta[0x12], meta[0x13], meta[0x14], meta[0x15],
                    meta[0x16], meta[0x17],
                ]);
                let length = u32::from_be_bytes([meta[0x18], meta[0x19], meta[0x1A], meta[0x1B]]);
                let compression_end =
                    u32::from_be_bytes([meta[0x1C], meta[0x1D], meta[0x1E], meta[0x1F]]);
                (offset, length, compression_end)
            } else {
                let dec = self.block_processor.decrypt_metadata_section(&meta);
                let offset = u64::from_be_bytes([
                    dec[0], dec[1], dec[2], dec[3], dec[4], dec[5], dec[6], dec[7],
                ]);
                let length = u32::from_be_bytes([dec[8], dec[9], dec[10], dec[11]]);
                let compression_end = u32::from_be_bytes([dec[12], dec[13], dec[14], dec[15]]);
                (offset, length, compression_end)
            };

            Ok(BlockMetadata {
                hash: meta[..0x10].to_vec(),
                offset,
                length,
                compression_end,
            })
        } else if self.edat_header.flags_bits().contains(EdatFlag::Flag0x20) {
            // FLAG 0x20: metadata is interleaved before each block.
            let block_size = u64::from(self.edat_header.block_size);
            let stride = 0x20u64 + block_size;
            let block_base = (block_index as u64) * stride;

            let mut meta = [0u8; 0x20];
            self.read_exact_at(metadata_offset + block_base, &mut meta)?;

            let mut hash = vec![0u8; 0x14];
            for j in 0..0x10 {
                hash[j] = meta[j] ^ meta[j + 0x10];
            }

            let offset = metadata_offset + block_base + 0x20;
            let length = if block_index == (self.block_num - 1)
                && !self
                    .edat_header
                    .file_size
                    .is_multiple_of(u64::from(self.edat_header.block_size))
            {
                (self.edat_header.file_size % u64::from(self.edat_header.block_size)) as u32
            } else {
                self.edat_header.block_size
            };

            Ok(BlockMetadata {
                hash,
                offset,
                length,
                compression_end: 0,
            })
        } else {
            // Standard case: contiguous 0x10 metadata entries.
            let entry_off =
                metadata_offset + (block_index as u64) * (self.metadata_section_size as u64);
            let mut hash = vec![0u8; 0x10];
            self.read_exact_at(entry_off, &mut hash)?;

            let offset = metadata_offset
                + (block_index as u64) * u64::from(self.edat_header.block_size)
                + (self.block_num as u64) * (self.metadata_section_size as u64);

            let length = if block_index == (self.block_num - 1)
                && !self
                    .edat_header
                    .file_size
                    .is_multiple_of(u64::from(self.edat_header.block_size))
            {
                (self.edat_header.file_size % u64::from(self.edat_header.block_size)) as u32
            } else {
                self.edat_header.block_size
            };

            Ok(BlockMetadata {
                hash,
                offset,
                length,
                compression_end: 0,
            })
        }
    }

    /// Decrypt (and decompress, if needed) the SDAT payload into `out`.
    ///
    /// Returns the number of plaintext bytes written.
    ///
    /// # Errors
    ///
    /// This function will return an error if decryption or decompression fails,
    /// or if writing to `out` fails.
    pub fn decrypt_to_writer<W: Write>(&mut self, mut out: W) -> Result<u64, SdatError> {
        let mut total_written: u64 = 0;

        for block_index in 0..self.block_num {
            let meta = self.block_metadata(block_index)?;

            let pad_len = meta.length as usize;
            let padded_len = (pad_len + 0xF) & 0xFFFFFFF0;

            let mut enc = vec![0u8; padded_len];
            self.read_exact_at(meta.offset, &mut enc)?;

            let dec = self.block_processor.decrypt_data_block(
                &enc,
                DecryptBlockOptions {
                    block_metadata: meta.clone(),
                    block_index: block_index as u32,
                    edat_header: self.edat_header.clone(),
                    npd_header: self.npd_header.clone(),
                    crypt_key: self.crypt_key,
                },
            )?;

            if self.edat_header.flags_bits().contains(EdatFlag::Compressed)
                && meta.compression_end != 0
            {
                // Current implementation treats compressed SDAT as one block containing the full payload.
                let mut decompressed = vec![0u8; self.edat_header.file_size as usize];
                let n = crate::compression::decompress(&dec, &mut decompressed)?;
                out.write_all(&decompressed[..n])
                    .map_err(|e| SdatError::InvalidHeader(format!("Write failed: {e}")))?;
                total_written += n as u64;
                break;
            }
            out.write_all(&dec)
                .map_err(|e| SdatError::InvalidHeader(format!("Write failed: {e}")))?;
            total_written += dec.len() as u64;
        }

        Ok(total_written)
    }

    /// Convenience helper: decrypt into a Vec.
    ///
    /// # Errors
    ///
    /// This function will return an error if decryption fails.
    pub fn decrypt_to_vec(&mut self) -> Result<Vec<u8>, SdatError> {
        let mut buf = Vec::with_capacity(self.edat_header.file_size as usize);
        self.decrypt_to_writer(&mut buf)?;
        Ok(buf)
    }

    /// Return the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}
