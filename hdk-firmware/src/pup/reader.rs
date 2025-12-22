use std::io::{self, Read, Seek, SeekFrom};

use byteorder::{BigEndian, ReadBytesExt};
use sha1_smol::Sha1;
use thiserror::Error;

use super::structs::{PupEntryMetadata, PupFileInfo, PupHash, PupHeader, PupMagic};

const PUP_HEADER_SIZE: u64 = 8 * 6;
const PUP_FILEINFO_SIZE: u64 = 8 * 3 + 8;
const PUP_HASH_SIZE: u64 = 8 + 20 + 4;

#[derive(Debug, Error)]
pub enum PupError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid PUP magic")]
    InvalidMagic,

    #[error("invalid file_count in header")]
    InvalidFileCount,

    #[error("file size doesn't match header_length/data_length")]
    ExpectedSizeMismatch,

    #[error("entry index out of range")]
    EntryIndex,

    #[error("entry offsets out of bounds")]
    EntryOutOfBounds,

    #[error("hash mismatch for entry {entry_id:#x}")]
    HashMismatch { entry_id: u64 },
}

/// Streaming PUP reader.
///
/// Similar to the SHARC reader, this parses the header + tables once, then provides
/// `entry_reader()` which returns a limited stream for an entry.
pub struct PupArchive<R: Read + Seek> {
    inner: R,
    header: PupHeader,
    files: Vec<PupFileInfo>,
    hashes: Vec<PupHash>,
    file_size: u64,
}

impl<R: Read + Seek> PupArchive<R> {
    pub fn open(mut inner: R) -> Result<Self, PupError> {
        // Compute file size.
        let file_size = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;

        if file_size < PUP_HEADER_SIZE {
            return Err(PupError::ExpectedSizeMismatch);
        }

        // Parse header.
        let mut magic_bytes = [0u8; 8];
        inner.read_exact(&mut magic_bytes)?;
        let magic = PupMagic(magic_bytes);

        let package_version = inner.read_u64::<BigEndian>()?;
        let image_version = inner.read_u64::<BigEndian>()?;
        let file_count = inner.read_u64::<BigEndian>()?;
        let header_length = inner.read_u64::<BigEndian>()?;
        let data_length = inner.read_u64::<BigEndian>()?;

        let header = PupHeader {
            magic,
            package_version,
            image_version,
            file_count,
            header_length,
            data_length,
        };

        if !header.magic.is_valid() {
            return Err(PupError::InvalidMagic);
        }

        if header.file_count == 0 {
            return Err(PupError::InvalidFileCount);
        }

        // Basic size sanity check.
        if file_size < header.header_length
            || file_size
                .saturating_sub(header.header_length)
                .lt(&header.data_length)
        {
            return Err(PupError::ExpectedSizeMismatch);
        }

        // Additional sanity check: ensure header_length can at least contain the tables.
        let min_header_length = PUP_HEADER_SIZE
            + header.file_count * PUP_FILEINFO_SIZE
            + header.file_count * PUP_HASH_SIZE;
        if header.header_length < min_header_length {
            return Err(PupError::ExpectedSizeMismatch);
        }

        // File table.
        let count = header.file_count as usize;
        let mut files = Vec::with_capacity(count);
        for _ in 0..count {
            let entry_id = inner.read_u64::<BigEndian>()?;
            let data_offset = inner.read_u64::<BigEndian>()?;
            let data_len = inner.read_u64::<BigEndian>()?;
            let mut padding = [0u8; 8];
            inner.read_exact(&mut padding)?;

            files.push(PupFileInfo {
                entry_id,
                data_offset,
                data_len,
                padding,
            });
        }

        // Hash table.
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            let entry_id = inner.read_u64::<BigEndian>()?;
            let mut hash = [0u8; 20];
            let mut padding = [0u8; 4];
            inner.read_exact(&mut hash)?;
            inner.read_exact(&mut padding)?;
            hashes.push(PupHash {
                entry_id,
                hash,
                padding,
            });
        }

        Ok(Self {
            inner,
            header,
            files,
            hashes,
            file_size,
        })
    }

    pub const fn header(&self) -> &PupHeader {
        &self.header
    }

    pub fn file_entries(&self) -> &[PupFileInfo] {
        &self.files
    }

    pub fn hash_entries(&self) -> &[PupHash] {
        &self.hashes
    }

    pub const fn len(&self) -> usize {
        self.files.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn find_entry(&self, entry_id: u64) -> Option<usize> {
        self.files.iter().position(|e| e.entry_id == entry_id)
    }

    pub fn entry_metadata(&self, index: usize) -> Result<PupEntryMetadata, PupError> {
        let file = *self.files.get(index).ok_or(PupError::EntryIndex)?;
        let hash = self
            .hashes
            .iter()
            .find(|h| h.entry_id == file.entry_id)
            .map(|h| h.hash);

        Ok(PupEntryMetadata {
            entry_id: file.entry_id,
            data_offset: file.data_offset,
            data_len: file.data_len,
            hash,
        })
    }

    pub fn entries_metadata(
        &self,
    ) -> impl Iterator<Item = Result<PupEntryMetadata, PupError>> + '_ {
        (0..self.files.len()).map(|i| self.entry_metadata(i))
    }

    /// Returns a limited reader for the entry data.
    ///
    /// This borrows `self` mutably because it seeks the underlying reader.
    pub fn entry_reader<'a>(&'a mut self, index: usize) -> Result<Box<dyn Read + 'a>, PupError> {
        let file = *self.files.get(index).ok_or(PupError::EntryIndex)?;

        let start = file.data_offset;
        let end = file
            .data_offset
            .checked_add(file.data_len)
            .ok_or(PupError::EntryOutOfBounds)?;

        if end > self.file_size {
            return Err(PupError::EntryOutOfBounds);
        }

        self.inner.seek(SeekFrom::Start(start))?;
        Ok(Box::new((&mut self.inner).take(file.data_len)))
    }

    /// Read an entry fully into memory.
    pub fn read_entry(&mut self, index: usize) -> Result<Vec<u8>, PupError> {
        let mut r = self.entry_reader(index)?;
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Read an entry fully and verify its SHA-1 matches the hash table (if present).
    pub fn read_entry_verified(&mut self, index: usize) -> Result<Vec<u8>, PupError> {
        let meta = self.entry_metadata(index)?;
        let data = self.read_entry(index)?;

        if let Some(expected) = meta.hash {
            let actual = Sha1::from(&data).digest().bytes();
            if actual != expected {
                return Err(PupError::HashMismatch {
                    entry_id: meta.entry_id,
                });
            }
        }

        Ok(data)
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be64(x: u64) -> [u8; 8] {
        x.to_be_bytes()
    }

    #[test]
    fn parses_minimal_pup_and_streams_entries() {
        // Build a minimal PUP with 2 entries.
        let entry_a_id = 0x100u64;
        let entry_b_id = 0x300u64;
        let data_a = b"FW_VER".to_vec();
        let data_b = b"TAR_BYTES".to_vec();

        // Layout: header(48) + file_tbl(2*32) + hash_tbl(2*32) = 176 bytes.
        let header_length = 48u64 + 2 * 32u64 + 2 * 32u64;
        let data_offset_a = header_length;
        let data_offset_b = data_offset_a + data_a.len() as u64;
        let data_length = (data_a.len() + data_b.len()) as u64;

        let mut buf = Vec::new();
        buf.extend_from_slice(super::super::structs::PUP_MAGIC);
        buf.extend_from_slice(&be64(1)); // package_version
        buf.extend_from_slice(&be64(1)); // image_version
        buf.extend_from_slice(&be64(2)); // file_count
        buf.extend_from_slice(&be64(header_length));
        buf.extend_from_slice(&be64(data_length));

        // file tbl
        for (id, off, len) in [
            (entry_a_id, data_offset_a, data_a.len() as u64),
            (entry_b_id, data_offset_b, data_b.len() as u64),
        ] {
            buf.extend_from_slice(&be64(id));
            buf.extend_from_slice(&be64(off));
            buf.extend_from_slice(&be64(len));
            buf.extend_from_slice(&[0u8; 8]);
        }

        // hash tbl
        for (id, data) in [(entry_a_id, &data_a), (entry_b_id, &data_b)] {
            buf.extend_from_slice(&be64(id));
            let h = Sha1::from(data.as_slice()).digest().bytes();
            buf.extend_from_slice(&h);
            buf.extend_from_slice(&[0u8; 4]);
        }

        // data
        buf.extend_from_slice(&data_a);
        buf.extend_from_slice(&data_b);

        let cur = io::Cursor::new(buf);
        let mut pup = PupArchive::open(cur).unwrap();

        assert_eq!(pup.header().file_count, 2);
        assert_eq!(pup.len(), 2);

        let a = pup.read_entry_verified(0).unwrap();
        let b = pup.read_entry_verified(1).unwrap();
        assert_eq!(a, data_a);
        assert_eq!(b, data_b);

        // streaming read
        let mut r = pup.entry_reader(1).unwrap();
        let mut streamed = Vec::new();
        r.read_to_end(&mut streamed).unwrap();
        assert_eq!(streamed, data_b);
    }
}
