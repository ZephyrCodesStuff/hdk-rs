use byteorder::{BigEndian, WriteBytesExt};
use std::io::{self, Write};

use crate::COMPRESSION_SCRATCH;

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

    let src_size = self.raw_buffer.len();

    let compressed_result: Vec<u8> = COMPRESSION_SCRATCH.with(|scratch_cell| -> io::Result<Vec<u8>> {
        let mut scratch = scratch_cell.borrow_mut();
        
        // Ensure scratch has enough room for the worst-case scenario 
        // (Uncompressible data + small DEFLATE overhead)
        let max_dst_size = src_size + 128; 
        if scratch.len() < max_dst_size {
            scratch.resize(max_dst_size, 0);
        }

        #[cfg(feature = "isal")]
        {
            // Use ISA-L's low-level igzip for total control
            let mut encoder = isal::write::DeflateEncoder::new(&mut scratch[..], isal::CompressionLevel::best()); 
            let bytes_written = encoder.write(&self.raw_buffer)?;
            encoder.flush()?;
            
            // explicitly name the error type so `Ok(...)` isn’t ambiguous
            Ok::<Vec<u8>, io::Error>(scratch[..bytes_written].to_vec())
        }

        #[cfg(not(feature = "isal"))]
        {
            // Fallback to flate2 (this still allocates a Vec, unfortunately)
            use flate2::{Compression, write::DeflateEncoder};
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
            encoder.write_all(&self.raw_buffer)?;
            encoder.finish()
        }
    })?;


    // 3. Write out to the inner writer
    let writer = self.inner.as_mut().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "Writer closed")
    })?;

    let (chunk_body, comp_size) = if compressed_result.len() >= src_size {
        (self.raw_buffer.as_slice(), src_size)
    } else {
        (compressed_result.as_slice(), compressed_result.len())
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
