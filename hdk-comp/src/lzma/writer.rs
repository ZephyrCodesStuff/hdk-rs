use std::io::{self, Write};

use byteorder::{BigEndian, WriteBytesExt};
use lzma_rust2::LzmaWriter;

use crate::lzma::{MAGIC, SEGMENT_SIZE};


pub struct SegmentedLzmaWriter<W: Write> {
    inner: Option<W>,

    raw_buffer: Vec<u8>,
    completed_segments: Vec<(Vec<u8>, u16, usize)>,
    total_uncompressed_size: u32,
}

impl<W: Write> SegmentedLzmaWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner: Some(inner),
            raw_buffer: Vec::with_capacity(SEGMENT_SIZE),
            completed_segments: Vec::new(),
            total_uncompressed_size: 0,
        }
    }

    /// Flushes the current raw_buffer into a compressed segment
    fn compress_current_chunk(&mut self) -> io::Result<()> {
        if self.raw_buffer.is_empty() {
            return Ok(());
        }

        let uncompressed_len = self.raw_buffer.len();
        self.total_uncompressed_size += uncompressed_len as u32;

        let mut compressed_output = Vec::new();
        let mut encoder = LzmaWriter::new_use_header(
            &mut compressed_output,
            &super::LMZA_OPTIONS,
            Some(uncompressed_len as u64),
        ).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        encoder.write_all(&self.raw_buffer)?;
        encoder.finish().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let compressed_size = compressed_output.len();
        
        if compressed_size > 0xFFFF {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Segment compressed size too large for u16"));
        }

        self.completed_segments.push((
            compressed_output, 
            compressed_size as u16, 
            uncompressed_len
        ));

        self.raw_buffer.clear();
        Ok(())
    }

    /// Finalizes the file format. MUST be called to write data to disk.
    pub fn finish(mut self) -> io::Result<W> {
        self.compress_current_chunk()?;

        let mut writer = self.inner.take().unwrap();
        let segment_count = self.completed_segments.len();

        if segment_count > 0xFFFF {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Too many segments (>65535)"));
        }

        // Calculate file layout
        let header_fixed_size = 16;
        let table_size = segment_count * 8;
        let raw_header_end = header_fixed_size + table_size;
        
        // Padding for the header section
        let header_padding = (16 - (raw_header_end % 16)) % 16;
        let header_total_size = raw_header_end + header_padding;

        // Write file header
        writer.write_all(MAGIC)?;                // 0-3: Magic
        writer.write_all(&[1, 5])?;              // 4-5: Type, Version
        writer.write_u16::<BigEndian>(segment_count as u16)?; // 6-7: Count
        writer.write_u32::<BigEndian>(self.total_uncompressed_size)?; // 8-11: Uncompressed Size
        
        // Calculate compressed size
        let mut total_compressed_file_size = header_total_size as u32;
        for (seg_data, _, _) in &self.completed_segments {
            let seg_padding = (16 - (seg_data.len() % 16)) % 16;
            total_compressed_file_size += (seg_data.len() + seg_padding) as u32;
        }
        writer.write_u32::<BigEndian>(total_compressed_file_size)?;

        // Writing segments table
        let mut running_offset = header_total_size;

        for (seg_data, c_size, u_size) in &self.completed_segments {
            let stored_u_size = if *u_size == 65536 { 0 } else { *u_size as u16 };
            
            writer.write_u16::<BigEndian>(*c_size)?;
            writer.write_u16::<BigEndian>(stored_u_size)?;
            
            // QUIRK: Offset | 1
            let offset_val = (running_offset as i32) | 1; 
            writer.write_i32::<BigEndian>(offset_val)?;

            // Advance offset
            let padding = (16 - (seg_data.len() % 16)) % 16;
            running_offset += seg_data.len() + padding;
        }

        // Pad header + segment table if necessary
        writer.write_all(&vec![0u8; header_padding])?;

        // Write segments
        for (seg_data, _, _) in &self.completed_segments {
            writer.write_all(seg_data)?;
            
            // QUIRK: Segment Padding
            let padding = (16 - (seg_data.len() % 16)) % 16;
            if padding > 0 {
                writer.write_all(&vec![0u8; padding])?;
            }
        }

        Ok(writer)
    }
}

impl<W: Write> Write for SegmentedLzmaWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cursor = 0;
        
        while cursor < buf.len() {
            let space_left = SEGMENT_SIZE - self.raw_buffer.len();
            let to_copy = std::cmp::min(space_left, buf.len() - cursor);
            
            self.raw_buffer.extend_from_slice(&buf[cursor..cursor + to_copy]);
            cursor += to_copy;

            if self.raw_buffer.len() == SEGMENT_SIZE {
                self.compress_current_chunk()?;
            }
        }
        
        Ok(cursor)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Note: We DO NOT compress partial chunks on flush() because 
        // that would create tiny segments and ruin the "64KB block" structure.
        // We only flush to the inner writer when finish() is called.
        Ok(())
    }
}