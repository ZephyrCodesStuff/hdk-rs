use std::io::{self, Read, Seek, SeekFrom};

use byteorder::{BigEndian, ReadBytesExt};

use crate::lzma::segment::SegmentEntry;

pub struct SegmentedLzmaReader<R: Read + Seek> {
    inner: R,
    segments: Vec<SegmentEntry>,
    
    // State
    current_segment_idx: usize,
    current_data: Vec<u8>,
    cursor_pos: usize,
}

impl<R: Read + Seek> SegmentedLzmaReader<R> {
    pub fn new(mut inner: R) -> io::Result<Self> {
        // Validate Magic
        let mut magic = [0u8; 4];
        inner.read_exact(&mut magic)?;
        if magic != super::MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid magic"));
        }

        // Read Header Info
        inner.seek(SeekFrom::Start(6))?;
        let count = inner.read_u16::<BigEndian>()?;
        
        // Skip global sizes
        inner.seek(SeekFrom::Current(8))?; 

        // Parse Segment Table
        let mut segments = Vec::with_capacity(count as usize);
        
        for _ in 0..count {
            let c_size = inner.read_u16::<BigEndian>()?;
            let u_size = inner.read_u16::<BigEndian>()?;
            let offset = inner.read_i32::<BigEndian>()?;

            // Resolve the sentinel size
            let u_size = if u_size == 0 { 65536 } else { u32::from(u_size) };

            // The final bit is used to indicate whether this segment is compressed or not.
            let final_offset = (offset & !1) as u64;

            segments.push(SegmentEntry {
                compressed_size: c_size,
                uncompressed_size: u_size,
                file_offset: final_offset,
            });
        }

        Ok(Self {
            inner,
            segments,
            current_segment_idx: 0,
            current_data: Vec::new(),
            cursor_pos: 0,
        })
    }

    /// Loads the segment at `idx` from disk and decompresses it
    fn load_segment(&mut self, idx: usize) -> io::Result<()> {
        if idx >= self.segments.len() {
            return Ok(()); // EOF
        }

        let seg = &self.segments[idx];

        // Seek where the header said
        self.inner.seek(SeekFrom::Start(seg.file_offset))?;

        // Read the compressed size
        let mut c_buf = vec![0u8; seg.compressed_size as usize];
        self.inner.read_exact(&mut c_buf)?;

        // Decompress using standard LZMA
        // We use a large mem limit because we know these are 64k chunks
        let mut decoder = lzma_rust2::LzmaReader::new_mem_limit(
            io::Cursor::new(c_buf), 
            u32::MAX, 
            None
        ).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        self.current_data.clear();
        
        // Check if we can pre-allocate to save re-allocs
        self.current_data.reserve(seg.uncompressed_size as usize);
        decoder.read_to_end(&mut self.current_data)?;

        self.cursor_pos = 0;
        self.current_segment_idx = idx;
        
        Ok(())
    }
}

// Standard Read implementation (Boilerplate)
impl<R: Read + Seek> Read for SegmentedLzmaReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we have no data, or finished the current segment, try to load the relevant one
        if self.current_data.is_empty() || self.cursor_pos >= self.current_data.len() {
            // Attempt to load next segment
            // Note: In a real Seek implementation, we'd calculate which segment we need
            // based on a virtual position. Here we just go sequential for `read`.
             if self.current_data.is_empty() && self.current_segment_idx == 0 {
                 self.load_segment(0)?;
             } else if self.cursor_pos >= self.current_data.len() {
                 self.load_segment(self.current_segment_idx + 1)?;
             }
        }

        // If still empty after trying to load, we are at EOF
        if self.cursor_pos >= self.current_data.len() {
            return Ok(0);
        }

        let available = self.current_data.len() - self.cursor_pos;
        let to_read = std::cmp::min(available, buf.len());
        
        buf[..to_read].copy_from_slice(&self.current_data[self.cursor_pos..self.cursor_pos + to_read]);
        self.cursor_pos += to_read;
        
        Ok(to_read)
    }
}