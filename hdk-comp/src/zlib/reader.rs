use byteorder::{BigEndian, ReadBytesExt};
use flate2::{Decompress, read::ZlibDecoder};
use std::io::{self, Read};

use super::EDGE_ZLIB_CHUNK_HEADER_SIZE;

pub struct SegmentedZlibReader<R: Read> {
    inner: R,
    current_chunk: Vec<u8>,
    cursor: usize,
}

impl<R: Read> SegmentedZlibReader<R> {
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            current_chunk: Vec::new(),
            cursor: 0,
        }
    }

    /// Tries to load the next chunk from the stream.
    /// Returns Ok(true) if a chunk was loaded, Ok(false) if EOF.
    fn load_next_chunk(&mut self) -> io::Result<bool> {
        let mut header = [0u8; EDGE_ZLIB_CHUNK_HEADER_SIZE];

        // Try to read header
        match self.inner.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e),
        }

        let mut header_slice = &header[..];
        let src_size = header_slice.read_u16::<BigEndian>()? as usize;
        let comp_size = header_slice.read_u16::<BigEndian>()? as usize;

        // Read the chunk body
        let mut chunk_data = vec![0u8; comp_size];
        self.inner.read_exact(&mut chunk_data)?;

        self.current_chunk.clear();
        self.cursor = 0;

        if src_size == comp_size {
            // Uncompressed chunk
            self.current_chunk = chunk_data;
        } else {
            // Compressed chunk
            self.current_chunk.reserve(src_size);
            let no_header = Decompress::new(false);
            let mut decoder = ZlibDecoder::new_with_decompress(&chunk_data[..], no_header);
            decoder.read_to_end(&mut self.current_chunk)?;
        }

        Ok(true)
    }
}

impl<R: Read> Read for SegmentedZlibReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if (self.current_chunk.is_empty() || self.cursor >= self.current_chunk.len())
            && !self.load_next_chunk()? {
                return Ok(0); // EOF
            }

        let available = self.current_chunk.len() - self.cursor;
        let to_read = std::cmp::min(available, buf.len());

        buf[..to_read].copy_from_slice(&self.current_chunk[self.cursor..self.cursor + to_read]);
        self.cursor += to_read;

        Ok(to_read)
    }
}
