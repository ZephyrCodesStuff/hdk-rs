use crate::sce::errors::SceError;
use crate::sce::structs::{SCE_METADATA_INFO_SIZE, SCE_SIGNATURE_SIZE, SCESignature};
use crate::sce::{SCE_METADATA_SECTION_HEADER_SIZE, crypto};
use aes::cipher::KeyIvInit;
use byteorder::{BigEndian, WriteBytesExt};
use ctr::cipher::StreamCipher;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Metadata for a section to be added to the SCE package.
#[derive(Debug, Clone)]
pub struct SectionMeta {
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

/// Streaming writer for SCE packages. Requires a seekable writer to patch header
/// fields after writing metadata and data.
pub struct SceWriter<W: Write + Seek> {
    inner: W,
    version: u32,
    se_flags: u16,
    se_type: u16,
    sections: Vec<SectionMeta>,
    keys: Vec<[u8; 16]>,
    meta_key: [u8; 16],
    meta_iv: [u8; 16],
    debug: bool,
}

impl<W: Write + Seek> SceWriter<W> {
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            version: 1,
            se_flags: 0,
            se_type: 0,
            sections: Vec::new(),
            keys: Vec::new(),
            meta_key: [0u8; 16],
            meta_iv: [0u8; 16],
            debug: true,
        }
    }

    /// Set debug flag (if true, metadata info will not be encrypted).
    pub const fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub const fn set_version(&mut self, v: u32) {
        self.version = v;
    }

    pub const fn set_se_flags(&mut self, f: u16) {
        self.se_flags = f;
    }

    pub const fn set_se_type(&mut self, t: u16) {
        self.se_type = t;
    }

    /// Set the metadata key/iv used to encrypt metadata headers (these are stored
    /// in the metadata info and will be encrypted with the provided ERK/RIV by the caller).
    pub const fn set_meta_key_iv(&mut self, key: [u8; 16], iv: [u8; 16]) {
        self.meta_key = key;
        self.meta_iv = iv;
    }

    /// Add a key that will be written into the key table. Returned index is used
    /// by `SectionMeta.key_idx` and `iv_idx`.
    pub fn add_key(&mut self, key: [u8; 16]) -> usize {
        self.keys.push(key);
        self.keys.len() - 1
    }

    /// Add a section metadata entry. The actual section bytes will be provided
    /// during `finish` via the callback.
    pub fn add_section(&mut self, meta: SectionMeta) {
        self.sections.push(meta);
    }

    /// Finish writing the package. The callback is invoked once per section in
    /// the same order as `add_section` and must write exactly `data_size` bytes
    /// for that section.
    ///
    /// If `keypair` is provided, the package will be signed with ECDSA and a
    /// signature block will be written. This requires `W: Read` to read back
    /// the header data for signing.
    pub fn finish<F>(
        mut self,
        erk: &[u8; 32],
        riv: &[u8; 16],
        keypair: Option<&crypto::EcdsaKeypair>,
        mut write_section: F,
    ) -> Result<W, SceError>
    where
        F: FnMut(usize, &mut dyn Write) -> io::Result<()>,
        W: Read,
    {
        // Compute metadata structures in memory first.
        let section_count = self.sections.len() as u32;
        let key_count = self.keys.len() as u32;

        // metadata info: 64 bytes (meta_key + padding + meta_iv + padding)
        let mut meta_info = vec![0u8; SCE_METADATA_INFO_SIZE];
        meta_info[0..16].copy_from_slice(&self.meta_key);
        // key_pad stays zero
        meta_info[32..48].copy_from_slice(&self.meta_iv);
        // iv_pad stays zero

        // Calculate signature_input_length if signing, otherwise 0
        let sig_input_length: u64 = if keypair.is_some() {
            32 // SCE header
            + SCE_METADATA_INFO_SIZE as u64
            + 32 // metadata header
            + (SCE_METADATA_SECTION_HEADER_SIZE as u64 * section_count as u64)
            + (16 * key_count as u64)
        } else {
            0
        };

        // metadata headers
        // MetadataHeader: 8 + 4*6 = 32 bytes
        let mut meta_headers = Vec::new();
        meta_headers.extend_from_slice(&sig_input_length.to_be_bytes()); // signature_input_length
        meta_headers.extend_from_slice(&0u32.to_be_bytes()); // unknown_0
        meta_headers.extend_from_slice(&section_count.to_be_bytes());
        meta_headers.extend_from_slice(&key_count.to_be_bytes());
        meta_headers.extend_from_slice(&0u32.to_be_bytes()); // opt_header_size
        meta_headers.extend_from_slice(&0u32.to_be_bytes()); // unknown_1
        meta_headers.extend_from_slice(&0u32.to_be_bytes()); // unknown_2

        // Reserve space for section headers; we'll fill known fields now and patch
        // data_offset/data_size later after writing the actual section bytes.
        let mut section_headers_bytes =
            vec![0u8; SCE_METADATA_SECTION_HEADER_SIZE * self.sections.len()];
        let mut section_header_entry_positions: Vec<usize> = Vec::new();

        {
            let mut sh_cursor = std::io::Cursor::new(&mut section_headers_bytes[..]);
            for s in &self.sections {
                // record position where data_offset (u64) will be written
                let entry_pos = sh_cursor.position() as usize;
                section_header_entry_positions.push(entry_pos);

                // write placeholder data_offset (u64)
                sh_cursor.write_all(&0u64.to_be_bytes()).unwrap();
                // write placeholder data_size (u64)
                sh_cursor.write_all(&0u64.to_be_bytes()).unwrap();
                // data_type, program_idx
                sh_cursor.write_all(&s.data_type.to_be_bytes()).unwrap();
                sh_cursor.write_all(&s.program_idx.to_be_bytes()).unwrap();
                // hashed, sha1_idx, encrypted, key_idx, iv_idx, compressed
                sh_cursor.write_all(&s.hashed.to_be_bytes()).unwrap();
                sh_cursor.write_all(&s.sha1_idx.to_be_bytes()).unwrap();
                sh_cursor.write_all(&s.encrypted.to_be_bytes()).unwrap();
                sh_cursor.write_all(&s.key_idx.to_be_bytes()).unwrap();
                sh_cursor.write_all(&s.iv_idx.to_be_bytes()).unwrap();
                sh_cursor.write_all(&s.compressed.to_be_bytes()).unwrap();
            }
        }

        // key table bytes
        let mut key_table_bytes = Vec::new();
        for k in &self.keys {
            key_table_bytes.extend_from_slice(k);
        }

        // write header with placeholders
        // SCE header: magic(4) version(4) se_flags(2) se_type(2) se_meta(4) se_hsize(8) se_esize(8)
        self.inner.write_all(b"SCE\0")?;
        self.inner.write_u32::<BigEndian>(self.version)?;
        let se_flags_to_write = self.se_flags | if self.debug { 0x8000 } else { 0 };
        self.inner.write_u16::<BigEndian>(se_flags_to_write)?;
        self.inner.write_u16::<BigEndian>(self.se_type)?;
        // se_meta: we place metadata immediately after header, so se_meta = 0
        self.inner.write_u32::<BigEndian>(0)?;

        // placeholders for se_hsize and se_esize, will patch later
        let se_hsize_pos = self.inner.stream_position()?;
        self.inner.write_u64::<BigEndian>(0)?; // se_hsize
        self.inner.write_u64::<BigEndian>(0)?; // se_esize

        // Metadata info area: encrypt with ERK/RIV unless debug is set.
        let mut meta_info_to_write = meta_info.clone();
        if !self.debug {
            crypto::aes_encrypt_cbc(erk, riv, &mut meta_info_to_write)
                .map_err(|_| SceError::InvalidMetadata)?;
        }
        self.inner.write_all(&meta_info_to_write)?;

        // Append section headers and key table to meta_headers before encrypting
        meta_headers.extend_from_slice(&section_headers_bytes);
        meta_headers.extend_from_slice(&key_table_bytes);

        // Encrypt metadata headers using meta_key/meta_iv (AES-CTR)
        let mut encrypted_meta_headers = meta_headers.clone();
        crypto::aes_decrypt_ctr(&self.meta_key, &self.meta_iv, &mut encrypted_meta_headers)
            .map_err(|_| SceError::InvalidMetadata)?;
        // Remember where metadata headers are written so we can patch them later
        let headers_start_pos = self.inner.stream_position()?;
        self.inner.write_all(&encrypted_meta_headers)?;

        // Write placeholder signature if signing
        let sig_pos = if keypair.is_some() {
            let pos = self.inner.stream_position()?;
            let placeholder_sig = [0u8; SCE_SIGNATURE_SIZE];
            self.inner.write_all(&placeholder_sig)?;
            Some(pos)
        } else {
            None
        };

        // Compute header sizes
        let header_end_pos = self.inner.stream_position()?;
        let se_hsize = header_end_pos; // total header size up to end of metadata headers (+ signature if present)

        // Data: stream each section and record actual offsets/sizes so we can patch section headers
        let mut actual_data_length: u64 = 0;
        let mut current_data_offset = se_hsize; // first section starts immediately after headers

        for (idx, s) in self.sections.iter().enumerate() {
            // record start position
            let start_pos = self.inner.stream_position()?;
            // Prepare writer chain: optionally encryption and/or compression
            if s.encrypted == 3 {
                // Create Ctr cipher for this section
                struct CtrWriter<'a, WW: Write> {
                    inner: &'a mut WW,
                    cipher: ctr::Ctr64BE<aes::Aes128>,
                }

                impl<WW: Write> Write for CtrWriter<'_, WW> {
                    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                        let mut tmp = buf.to_vec();
                        self.cipher.apply_keystream(&mut tmp);
                        self.inner.write_all(&tmp)?;
                        Ok(buf.len())
                    }
                    fn flush(&mut self) -> io::Result<()> {
                        self.inner.flush()
                    }
                }

                let key = &self.keys[s.key_idx as usize];
                let iv = &self.keys[s.iv_idx as usize];

                let cipher = ctr::Ctr64BE::<aes::Aes128>::new(key.into(), iv.into());
                let mut ctr_writer = CtrWriter {
                    inner: &mut self.inner,
                    cipher,
                };

                if s.compressed == 2 {
                    let mut encoder = flate2::write::ZlibEncoder::new(
                        &mut ctr_writer,
                        flate2::Compression::default(),
                    );
                    write_section(idx, &mut encoder).map_err(SceError::Io)?;
                    encoder.finish().map_err(SceError::Io)?;
                } else {
                    write_section(idx, &mut ctr_writer).map_err(SceError::Io)?;
                }
            } else {
                // not encrypted
                if s.compressed == 2 {
                    let mut encoder = flate2::write::ZlibEncoder::new(
                        &mut self.inner,
                        flate2::Compression::default(),
                    );
                    write_section(idx, &mut encoder).map_err(SceError::Io)?;
                    encoder.finish().map_err(SceError::Io)?;
                } else {
                    write_section(idx, &mut self.inner).map_err(SceError::Io)?;
                }
            }

            // compute actual size written for this section
            let end_pos = self.inner.stream_position()?;
            let actual_size = end_pos
                .checked_sub(start_pos)
                .ok_or(SceError::InvalidMetadata)?;

            // Patch in-memory meta_headers section header data_offset/data_size
            let section_entry_base = meta_headers.len()
                - (section_headers_bytes.len() + key_table_bytes.len())
                + section_header_entry_positions[idx];
            // write data_offset (BE)
            meta_headers[section_entry_base..section_entry_base + 8]
                .copy_from_slice(&current_data_offset.to_be_bytes());
            // write data_size (BE)
            meta_headers[section_entry_base + 8..section_entry_base + 16]
                .copy_from_slice(&actual_size.to_be_bytes());

            current_data_offset = current_data_offset
                .checked_add(actual_size)
                .ok_or(SceError::InvalidMetadata)?;
            actual_data_length = actual_data_length
                .checked_add(actual_size)
                .ok_or(SceError::InvalidMetadata)?;
        }

        // Re-encrypt patched metadata headers and overwrite the previous copy
        let mut patched_encrypted_meta_headers = meta_headers.clone();
        crypto::aes_decrypt_ctr(
            &self.meta_key,
            &self.meta_iv,
            &mut patched_encrypted_meta_headers,
        )
        .map_err(|_| SceError::InvalidMetadata)?;
        self.inner.seek(SeekFrom::Start(headers_start_pos))?;
        self.inner.write_all(&patched_encrypted_meta_headers)?;

        // Patch header: se_hsize and se_esize
        let se_esize = actual_data_length;
        self.inner.seek(SeekFrom::Start(se_hsize_pos))?;
        self.inner.write_u64::<BigEndian>(se_hsize)?;
        self.inner.write_u64::<BigEndian>(se_esize)?;

        // Sign the header if keypair provided
        if let (Some(kp), Some(sig_pos)) = (keypair, sig_pos) {
            // Read header data for signing (up to signature_input_length)
            self.inner.seek(SeekFrom::Start(0))?;
            let mut header_data = vec![0u8; sig_input_length as usize];
            self.inner.read_exact(&mut header_data)?;

            // Sign the header
            let (r, s) = crypto::ecdsa_sign(kp, &header_data).map_err(SceError::Io)?;

            // Write signature
            let signature = SCESignature {
                r,
                s,
                padding: [0u8; 6],
            };
            self.inner.seek(SeekFrom::Start(sig_pos))?;
            signature.write_to(&mut self.inner)?;
        }

        // Seek to end
        self.inner.seek(SeekFrom::End(0))?;

        Ok(self.inner)
    }
}

/// Re-sign an existing SCE file with a new ECDSA keypair.
///
/// This function reads the file, computes the signature over the header data
/// (up to signature_input_length), and writes the new signature in place.
///
/// Note: The file must have its metadata already decrypted (debug mode) or
/// you must provide the correct keys to decrypt it first.
pub fn resign_sce<RW: Read + Write + Seek>(
    file: &mut RW,
    keypair: &crypto::EcdsaKeypair,
    erk: &[u8; 32],
    riv: &[u8; 16],
) -> Result<SCESignature, SceError> {
    use crate::sce::reader::SceArchive;

    // Open and load metadata to get signature offset
    file.seek(SeekFrom::Start(0))?;

    // Read the entire file into memory for processing
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;

    let mut archive = SceArchive::open(std::io::Cursor::new(&file_data))?;
    archive.load_metadata(erk, riv)?;

    let sig_input_length = archive
        .signature_input_length()
        .ok_or(SceError::InvalidMetadata)?;

    let sig_offset = archive
        .signature_offset()
        .ok_or(SceError::InvalidMetadata)?;

    // Read header data for signing
    let header_data = &file_data[..sig_input_length as usize];

    // Sign
    let (r, s) = crypto::ecdsa_sign(keypair, header_data).map_err(SceError::Io)?;

    let signature = SCESignature {
        r,
        s,
        padding: [0u8; 6],
    };

    // Write new signature
    file.seek(SeekFrom::Start(sig_offset))?;
    signature.write_to(file)?;

    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sce::reader::SceArchive;

    #[test]
    fn writer_roundtrip_with_reader() {
        use std::io::Cursor;

        let mut out = Cursor::new(Vec::new());
        let mut w = SceWriter::new(&mut out);
        w.set_meta_key_iv([0x11; 16], [0x22; 16]);

        // add a key (same as iv for simplicity)
        let kidx = w.add_key([0xAA; 16]);

        let data_a = b"hello section a".to_vec();
        let data_b = b"section b contents".to_vec();

        w.add_section(SectionMeta {
            data_size: data_a.len() as u64,
            data_type: 1,
            program_idx: 0,
            hashed: 0,
            sha1_idx: 0,
            encrypted: 3,
            key_idx: kidx as u32,
            iv_idx: kidx as u32,
            compressed: 0,
        });
        w.add_section(SectionMeta {
            data_size: data_b.len() as u64,
            data_type: 2,
            program_idx: 0,
            hashed: 0,
            sha1_idx: 0,
            encrypted: 0,
            key_idx: 0,
            iv_idx: 0,
            compressed: 0,
        });

        // ERK/RIV (used to encrypt metadata info) - for now not used (debug behavior)
        let erk = [0x0u8; 32];
        let riv = [0x0u8; 16];

        let mut idx = 0usize;
        w.finish(&erk, &riv, None, |_i, out| {
            if idx == 0 {
                out.write_all(&data_a)?;
            } else {
                out.write_all(&data_b)?;
            }
            idx += 1;
            Ok(())
        })
        .expect("finish");

        // Re-open via reader
        let inner = out.into_inner();
        let mut r = SceArchive::open(Cursor::new(inner)).expect("open");
        r.load_metadata(&erk, &riv).expect("load metadata");
        let a = r.read_section(0).expect("read section 0");
        let b = r.read_section(1).expect("read section 1");

        assert_eq!(a, data_a);
        assert_eq!(b, data_b);
    }
}
