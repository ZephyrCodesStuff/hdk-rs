use byteorder::{BigEndian, WriteBytesExt};
use flate2::{Compression, write::DeflateEncoder};
use std::io::{self, Write};

use super::EDGE_ZLIB_CHUNK_SIZE_MAX;

pub struct SegmentedZlibWriter<W: Write> {
    inner: Option<W>,
    raw_buffer: Vec<u8>,
}

impl<W: Write> SegmentedZlibWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner: Some(inner),
            raw_buffer: Vec::with_capacity(EDGE_ZLIB_CHUNK_SIZE_MAX),
        }
    }

    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.raw_buffer.is_empty() {
            return Ok(());
        }

        let writer = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Writer closed"))?;

        let src_size = self.raw_buffer.len();

        // EdgeZLib chunks store raw DEFLATE streams (no zlib header).
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&self.raw_buffer)?;
        let compressed_data = encoder.finish()?;

        // If compression isn't beneficial, store the chunk uncompressed.
        let (chunk_body, comp_size) = if compressed_data.len() >= src_size {
            (self.raw_buffer.as_slice(), src_size)
        } else {
            (compressed_data.as_slice(), compressed_data.len())
        };

        if comp_size > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Compressed chunk size exceeded u16::MAX",
            ));
        }

        writer.write_u16::<BigEndian>(src_size as u16)?;
        writer.write_u16::<BigEndian>(comp_size as u16)?;
        writer.write_all(chunk_body)?;

        self.raw_buffer.clear();
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.flush_chunk()?;
        Ok(self.inner.take().unwrap())
    }
}

impl<W: Write> Write for SegmentedZlibWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cursor = 0;

        while cursor < buf.len() {
            let space = EDGE_ZLIB_CHUNK_SIZE_MAX - self.raw_buffer.len();
            let to_write = std::cmp::min(space, buf.len() - cursor);

            self.raw_buffer
                .extend_from_slice(&buf[cursor..cursor + to_write]);
            cursor += to_write;

            if self.raw_buffer.len() == EDGE_ZLIB_CHUNK_SIZE_MAX {
                self.flush_chunk()?;
            }
        }

        Ok(cursor)
    }

    fn flush(&mut self) -> io::Result<()> {
        // We do *not* flush partial chunks here, similar to the LZMA implementation,
        // because that would break the expected chunking strategy.
        // We only persist on finish().
        Ok(())
    }
}
