use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use crate::block::{DataBlockProcessor, METADATA_OFFSET};
use crate::crypto::SdatKeys;
use crate::error::SdatError;
use crate::headers::{EdatHeader, NpdHeader};
use crate::options::EncryptBlockOptions;

/// High-level SDAT writer.
///
/// This is a more Rust-friendly API over the legacy `repack_sdat` buffer-based function.
/// It currently builds the output in-memory and returns a `Vec<u8>`.
#[derive(Debug, Clone)]
pub struct SdatWriter {
    output_file_name: String,
    keys: SdatKeys,
}

impl SdatWriter {
    /// Create a new writer configuration.
    ///
    /// # Arguments
    ///
    /// * `output_file_name` - The output filename to embed in the SDAT header.
    /// * `keys` - The cryptographic keys required for encryption.
    ///
    /// # Errors
    ///
    /// This function will return an error if the provided output filename is empty.
    pub fn new(output_file_name: impl Into<String>, keys: SdatKeys) -> Result<Self, SdatError> {
        let output_file_name = output_file_name.into();
        if output_file_name.is_empty() {
            return Err(SdatError::InvalidHeader(
                "Output filename cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            output_file_name,
            keys,
        })
    }

    /// Repack plaintext bytes into an SDAT container, returning the full SDAT file bytes.
    ///
    /// # Errors
    ///
    /// This function will return an error if repacking to SDAT fails.
    pub fn write_to_vec(&self, input: &[u8]) -> Result<Vec<u8>, SdatError> {
        let mut out = Cursor::new(Vec::<u8>::new());
        let mut in_cur = Cursor::new(input);

        // Delegate to the streaming writer, using an in-memory Cursor as the output sink.
        let _ = SdatStreamWriter::new(&mut out, self.output_file_name.clone(), self.keys)?
            .write_from_reader_seekable(&mut in_cur)?;

        Ok(out.into_inner())
    }

    /// Convenience helper: read all plaintext from `reader`, then repack to SDAT.
    ///
    /// # Errors
    ///
    /// This function will return an error if reading from `reader` fails,
    /// or if repacking to SDAT fails.
    pub fn write_from_reader_to_vec(&self, mut reader: impl Read) -> Result<Vec<u8>, SdatError> {
        let mut input = Vec::new();
        reader
            .read_to_end(&mut input)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to read input: {e}")))?;
        self.write_to_vec(&input)
    }
}

/// Streaming SDAT writer.
///
/// Unlike `SdatWriter` (which returns a `Vec<u8>`), this writes directly to a seekable output.
///
/// Current behavior uses fixed parameters:
/// - block size: 0x8000
/// - compression: disabled
pub struct SdatStreamWriter<W: Write + Seek> {
    inner: W,
    output_file_name: String,
    block_size: u32,
    keys: SdatKeys,
}

impl<W: Write + Seek> SdatStreamWriter<W> {
    /// Create a new streaming SDAT writer.
    ///
    /// # Arguments
    ///
    /// * `inner` - The seekable writer to write the SDAT output to.
    /// * `output_file_name` - The output filename to embed in the SDAT header.
    /// * `keys` - The cryptographic keys required for encryption.
    ///
    /// # Errors
    ///
    /// This function will return an error if the provided output filename is empty.
    pub fn new(
        inner: W,
        output_file_name: impl Into<String>,
        keys: SdatKeys,
    ) -> Result<Self, SdatError> {
        let output_file_name = output_file_name.into();
        if output_file_name.is_empty() {
            return Err(SdatError::InvalidHeader(
                "Output filename cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            inner,
            output_file_name,
            block_size: 0x8000,
            keys,
        })
    }

    /// Override the block size (defaults to 0x8000).
    ///
    /// This is intentionally minimal: the reader already supports arbitrary block sizes.
    pub const fn with_block_size(mut self, block_size: u32) -> Self {
        self.block_size = block_size;
        self
    }

    /// Stream plaintext from a seekable reader, encrypt it into SDAT, and return the output + bytes written.
    ///
    /// # Errors
    ///
    /// This function will return an error if reading from `input` fails,
    /// or if writing to the underlying output fails.
    pub fn write_from_reader_seekable(
        mut self,
        input: &mut (impl Read + Seek),
    ) -> Result<(W, u64), SdatError> {
        let file_size = input
            .seek(SeekFrom::End(0))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek input: {e}")))?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek input: {e}")))?;

        if file_size == 0 {
            return Err(SdatError::InvalidFormat);
        }

        // 1) Build headers (mirrors repack_sdat)
        let content_id_string = NpdHeader::generate_content_id();
        let mut content_id = [0u8; 0x30];
        let content_bytes = content_id_string.as_bytes();
        let copy_len = content_bytes.len().min(0x30);
        content_id[..copy_len].copy_from_slice(&content_bytes[..copy_len]);

        let crypto_ctx = crate::crypto::CryptoContext::new(self.keys);

        let mut title_msg = Vec::with_capacity(0x30 + self.output_file_name.len());
        title_msg.extend_from_slice(&content_id);
        title_msg.extend_from_slice(self.output_file_name.as_bytes());
        let title_hash = crypto_ctx.aes_cmac(&self.keys.npdrm_omac_key_3, &title_msg);

        let mut npd_header = NpdHeader::new_sdat(content_id, [0u8; 16], title_hash);
        let mut npd_bytes = vec![0u8; NpdHeader::SIZE];
        npd_header.serialize(&mut npd_bytes)?;
        let dev_hash = crypto_ctx.aes_cmac(&self.keys.npdrm_omac_key_2, &npd_bytes[0..0x60]);
        npd_header.dev_hash = dev_hash;
        npd_header.serialize(&mut npd_bytes)?;

        let edat_header = EdatHeader::new_sdat(file_size, self.block_size, false);
        let mut edat_bytes = vec![0u8; EdatHeader::SIZE];
        edat_header.serialize(&mut edat_bytes)?;

        let crypt_key = crate::crypto::generate_sdat_key(&self.keys.sdat_key, &npd_header.dev_hash);

        // 2) Layout sizing
        let block_num = file_size.div_ceil(u64::from(self.block_size)) as usize;
        let metadata_section_size: usize = 0x10;
        let metadata_size = block_num * metadata_section_size;
        let data_start = METADATA_OFFSET as u64 + metadata_size as u64;

        // 3) Write initial fixed regions (placeholders for hashes/signature/metadata)
        self.inner
            .seek(SeekFrom::Start(0))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek output: {e}")))?;
        self.inner
            .write_all(&npd_bytes)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to write NPD header: {e}")))?;
        self.inner
            .write_all(&edat_bytes)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to write EDAT header: {e}")))?;

        // Zero-fill up to METADATA_OFFSET (0x100). This includes the future hash/signature area.
        let pos = self.inner.stream_position().map_err(|e| {
            SdatError::InvalidHeader(format!("Failed to query output position: {e}"))
        })?;
        if pos > METADATA_OFFSET as u64 {
            return Err(SdatError::InvalidHeader(
                "Output position exceeded metadata offset".to_string(),
            ));
        }
        let pad_len = (METADATA_OFFSET as u64 - pos) as usize;
        if pad_len > 0 {
            self.inner
                .write_all(&vec![0u8; pad_len])
                .map_err(|e| SdatError::InvalidHeader(format!("Failed to write padding: {e}")))?;
        }

        // Reserve metadata section.
        if metadata_size > 0 {
            self.inner
                .write_all(&vec![0u8; metadata_size])
                .map_err(|e| {
                    SdatError::InvalidHeader(format!("Failed to reserve metadata: {e}"))
                })?;
        }

        // Seek to start of data section and stream blocks.
        self.inner
            .seek(SeekFrom::Start(data_start))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek to data start: {e}")))?;

        let block_processor = DataBlockProcessor::new(self.keys);
        let mut metadata_buf = vec![0u8; metadata_size];
        let mut data_pos = data_start;

        for block_index in 0..block_num {
            let remaining = file_size
                .saturating_sub((block_index as u64) * u64::from(self.block_size))
                as usize;
            let to_read = remaining.min(self.block_size as usize);
            let mut plain = vec![0u8; to_read];
            input.read_exact(&mut plain).map_err(|e| {
                SdatError::InvalidHeader(format!("Failed to read input block: {e}"))
            })?;

            let (encrypted, hash) = block_processor.encrypt_data_block(
                &plain,
                EncryptBlockOptions {
                    block_index: block_index as u32,
                    edat_header: edat_header.clone(),
                    npd_header: npd_header.clone(),
                    crypt_key,
                },
            )?;

            // Fill metadata entry (hash only for non-compressed format).
            let meta_off = block_index * metadata_section_size;
            if meta_off + hash.len() > metadata_buf.len() {
                return Err(SdatError::BufferTooSmall {
                    needed: meta_off + hash.len(),
                    available: metadata_buf.len(),
                });
            }
            metadata_buf[meta_off..meta_off + hash.len()].copy_from_slice(&hash);

            self.inner.write_all(&encrypted).map_err(|e| {
                SdatError::InvalidHeader(format!("Failed to write encrypted block: {e}"))
            })?;
            data_pos += encrypted.len() as u64;
        }

        // Footer
        self.inner
            .write_all(&crate::crypto::SDAT_FOOTER_V1)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to write footer: {e}")))?;
        data_pos += crate::crypto::SDAT_FOOTER_V1.len() as u64;

        // 4) Patch metadata section
        self.inner
            .seek(SeekFrom::Start(METADATA_OFFSET as u64))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek to metadata: {e}")))?;
        if !metadata_buf.is_empty() {
            self.inner
                .write_all(&metadata_buf)
                .map_err(|e| SdatError::InvalidHeader(format!("Failed to write metadata: {e}")))?;
        }

        // 5) Compute and patch metadata hash / header hash / signature (mirrors repack_sdat)
        let hash_mode = if (edat_header.flags & crate::crypto::EDAT_FLAG_0X10) == 0 {
            0x02
        } else if (edat_header.flags & crate::crypto::EDAT_FLAG_0X20) == 0 {
            0x04
        } else {
            0x01
        };

        let version = 4;
        let hash_final = crypto_ctx.generate_hash(hash_mode, version, &crypt_key)?;

        let metadata_hash = if (hash_mode & 0xFF) == 0x01 {
            let h = crypto_ctx.hmac_sha1(&hash_final, &metadata_buf);
            let mut res = [0u8; 16];
            res.copy_from_slice(&h[..16]);
            res
        } else {
            crypto_ctx.aes_cmac(&hash_final, &metadata_buf)
        };

        // header_buffer is the first 0xA0 bytes: NPD (0x80) + EDAT (0x10) + metadata_hash (0x10)
        let mut header_buffer = Vec::with_capacity(0xA0);
        header_buffer.extend_from_slice(&npd_bytes);
        header_buffer.extend_from_slice(&edat_bytes);
        header_buffer.extend_from_slice(&metadata_hash);

        let header_hash = if (hash_mode & 0xFF) == 0x01 {
            let h = crypto_ctx.hmac_sha1(&hash_final, &header_buffer);
            let mut res = [0u8; 16];
            res.copy_from_slice(&h[..16]);
            res
        } else {
            crypto_ctx.aes_cmac(&hash_final, &header_buffer)
        };

        // Patch metadata hash (0x90..0xA0)
        self.inner.seek(SeekFrom::Start(0x90)).map_err(|e| {
            SdatError::InvalidHeader(format!("Failed to seek to metadata hash: {e}"))
        })?;
        self.inner
            .write_all(&metadata_hash)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to write metadata hash: {e}")))?;

        // Patch header hash (0xA0..0xB0)
        self.inner
            .seek(SeekFrom::Start(0xA0))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek to header hash: {e}")))?;
        self.inner
            .write_all(&header_hash)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to write header hash: {e}")))?;

        // Patch signature (0xB0..0x100) with the same deterministic pattern as repack_sdat.
        self.inner
            .seek(SeekFrom::Start(0xB0))
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to seek to signature: {e}")))?;
        let mut sig = [0u8; 0x50];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0xAA);
        }
        self.inner
            .write_all(&sig)
            .map_err(|e| SdatError::InvalidHeader(format!("Failed to write signature: {e}")))?;

        Ok((self.inner, data_pos))
    }
}
