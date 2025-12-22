use std::io::{self, Read, Write};

use byteorder::{BigEndian, WriteBytesExt};
use sha1_smol::Sha1;
use thiserror::Error;

use super::structs::{PUP_MAGIC, PupFileInfo};

#[derive(Debug, Error)]
pub enum PupWriteError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("no entries added")]
    NoEntries,

    #[error(
        "entry {entry_id:#x} length mismatch (expected {expected} bytes, wrote {actual} bytes)"
    )]
    EntryLengthMismatch {
        entry_id: u64,
        expected: u64,
        actual: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct StreamEntryMeta {
    entry_id: u64,
    data_len: u64,
    sha1: [u8; 20],
}

/// Streaming PUP writer.
///
/// Unlike `PupWriter`, this does not buffer payloads in memory.
/// Instead you add entry metadata (id/len/sha1) and provide a callback to stream
/// each entry's bytes during `finish_with`.
pub struct PupStreamWriter<W: Write> {
    inner: W,
    pub package_version: u64,
    pub image_version: u64,
    entries: Vec<StreamEntryMeta>,
}

impl<W: Write> PupStreamWriter<W> {
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            package_version: 1,
            image_version: 1,
            entries: Vec::new(),
        }
    }

    pub fn add_entry_meta(
        &mut self,
        entry_id: u64,
        data_len: u64,
        sha1: [u8; 20],
    ) -> Result<(), PupWriteError> {
        self.entries.push(StreamEntryMeta {
            entry_id,
            data_len,
            sha1,
        });
        Ok(())
    }

    /// Finish writing the PUP, streaming entry data via `write_entry_data`.
    ///
    /// The callback is invoked once per entry (in the same order as metadata was added).
    /// It must write exactly `data_len` bytes for that entry.
    pub fn finish_with<F>(mut self, mut write_entry_data: F) -> Result<W, PupWriteError>
    where
        F: FnMut(u64, u64, &mut dyn Write) -> io::Result<()>,
    {
        if self.entries.is_empty() {
            return Err(PupWriteError::NoEntries);
        }

        let file_count = self.entries.len() as u64;
        let header_length = 48u64 + file_count * 32u64 + file_count * 32u64;
        let data_length: u64 = self.entries.iter().map(|e| e.data_len).sum();

        // Header
        self.inner.write_all(PUP_MAGIC)?;
        self.inner.write_u64::<BigEndian>(self.package_version)?;
        self.inner.write_u64::<BigEndian>(self.image_version)?;
        self.inner.write_u64::<BigEndian>(file_count)?;
        self.inner.write_u64::<BigEndian>(header_length)?;
        self.inner.write_u64::<BigEndian>(data_length)?;

        // File table
        let mut data_offset = header_length;
        let mut file_infos: Vec<PupFileInfo> = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            let info = PupFileInfo {
                entry_id: e.entry_id,
                data_offset,
                data_len: e.data_len,
                padding: [0u8; 8],
            };
            file_infos.push(info);
            data_offset = data_offset.checked_add(info.data_len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "data length overflow")
            })?;
        }

        for info in &file_infos {
            self.inner.write_u64::<BigEndian>(info.entry_id)?;
            self.inner.write_u64::<BigEndian>(info.data_offset)?;
            self.inner.write_u64::<BigEndian>(info.data_len)?;
            self.inner.write_all(&info.padding)?;
        }

        // Hash table
        for e in &self.entries {
            self.inner.write_u64::<BigEndian>(e.entry_id)?;
            self.inner.write_all(&e.sha1)?;
            self.inner.write_all(&[0u8; 4])?;
        }

        // Data
        struct CountingWriter<'a> {
            inner: &'a mut dyn Write,
            written: u64,
        }

        impl Write for CountingWriter<'_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let n = self.inner.write(buf)?;
                self.written = self
                    .written
                    .checked_add(n as u64)
                    .ok_or_else(|| io::Error::other("write count overflow"))?;
                Ok(n)
            }

            fn flush(&mut self) -> io::Result<()> {
                self.inner.flush()
            }
        }

        for e in &self.entries {
            let mut cw = CountingWriter {
                inner: &mut self.inner,
                written: 0,
            };
            write_entry_data(e.entry_id, e.data_len, &mut cw)?;
            if cw.written != e.data_len {
                return Err(PupWriteError::EntryLengthMismatch {
                    entry_id: e.entry_id,
                    expected: e.data_len,
                    actual: cw.written,
                });
            }
        }

        Ok(self.inner)
    }
}

struct EntryToWrite {
    entry_id: u64,
    data: Vec<u8>,
    sha1: [u8; 20],
}

/// PUP writer with a SHARC-like API.
///
/// This supports streaming *input* via `add_entry_from_reader`, while still producing a valid
/// output by buffering entry payloads in memory until `finish()`.
pub struct PupWriter<W: Write> {
    inner: W,
    pub package_version: u64,
    pub image_version: u64,
    entries: Vec<EntryToWrite>,
}

impl<W: Write> PupWriter<W> {
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            package_version: 1,
            image_version: 1,
            entries: Vec::new(),
        }
    }

    /// Convenience: add an entry from a byte slice.
    ///
    /// # Errors
    ///
    /// This function will return an error if computing the SHA1 checksum fails.
    pub fn add_entry_from_bytes(
        &mut self,
        entry_id: u64,
        bytes: &[u8],
    ) -> Result<(), PupWriteError> {
        let sha1 = Sha1::from(bytes).digest().bytes();
        self.entries.push(EntryToWrite {
            entry_id,
            data: bytes.to_vec(),
            sha1,
        });
        Ok(())
    }

    /// Streaming input convenience: reads the whole reader into memory.
    ///
    /// # Errors
    ///
    /// This function will return an error if reading from `reader` fails.
    pub fn add_entry_from_reader<Rd: Read + ?Sized>(
        &mut self,
        entry_id: u64,
        reader: &mut Rd,
    ) -> Result<(), PupWriteError> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let sha1 = Sha1::from(&data).digest().bytes();
        self.entries.push(EntryToWrite {
            entry_id,
            data,
            sha1,
        });
        Ok(())
    }

    /// Finish writing the PUP, returning the underlying writer.
    ///
    /// # Errors
    ///
    /// This function will return an error if no entries were added,
    /// or if writing to the underlying writer fails.
    pub fn finish(self) -> Result<W, PupWriteError> {
        if self.entries.is_empty() {
            return Err(PupWriteError::NoEntries);
        }

        let mut stream = PupStreamWriter::new(self.inner);
        stream.package_version = self.package_version;
        stream.image_version = self.image_version;

        for e in &self.entries {
            stream.add_entry_meta(e.entry_id, e.data.len() as u64, e.sha1)?;
        }

        let mut entries = self.entries.into_iter();
        stream.finish_with(move |entry_id, expected_len, out| {
            let e = entries.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing entry payload during finish",
                )
            })?;

            if e.entry_id != entry_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "entry id mismatch: header expects {entry_id:#x}, got {:#x}",
                        e.entry_id
                    ),
                ));
            }
            if e.data.len() as u64 != expected_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "entry length mismatch",
                ));
            }

            out.write_all(&e.data)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pup::reader::PupArchive;

    #[test]
    fn writer_roundtrip_with_reader() {
        let mut out = Vec::new();
        let mut w = PupWriter::new(&mut out);

        w.add_entry_from_bytes(0x100, b"FW_VER").unwrap();
        w.add_entry_from_bytes(0x300, b"TAR_BYTES").unwrap();
        w.finish().unwrap();

        let cur = std::io::Cursor::new(out);
        let mut pup = PupArchive::open(cur).unwrap();

        let a = pup.read_entry_verified(0).unwrap();
        let b = pup.read_entry_verified(1).unwrap();
        assert_eq!(a, b"FW_VER");
        assert_eq!(b, b"TAR_BYTES");
    }
}
