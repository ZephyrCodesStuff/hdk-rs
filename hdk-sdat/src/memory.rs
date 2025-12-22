//! Memory buffer operations for safe SDAT processing

use crate::error::MemoryError;

/// Memory buffer for safe byte operations
pub struct MemoryBuffer {
    data: Vec<u8>,
    position: usize,
}

impl MemoryBuffer {
    /// Create a new memory buffer with specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            position: 0,
        }
    }

    /// Create a memory buffer from existing slice
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            position: 0,
        }
    }

    /// Read data from buffer into provided slice
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, MemoryError> {
        let available = self.data.len().saturating_sub(self.position);
        let to_read = buf.len().min(available);

        if to_read == 0 {
            return Ok(0);
        }

        buf[..to_read].copy_from_slice(&self.data[self.position..self.position + to_read]);
        self.position += to_read;

        Ok(to_read)
    }

    /// Write data from slice into buffer
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, MemoryError> {
        // Ensure we have enough capacity
        let required_size = self.position + buf.len();
        if self.data.len() < required_size {
            self.data.resize(required_size, 0);
        }

        self.data[self.position..self.position + buf.len()].copy_from_slice(buf);
        self.position += buf.len();

        Ok(buf.len())
    }

    /// Seek to specific position in buffer
    pub fn seek(&mut self, pos: usize) -> Result<(), MemoryError> {
        if pos > self.data.len() {
            return Err(MemoryError::InvalidSeekPosition { position: pos });
        }

        self.position = pos;
        Ok(())
    }

    /// Get current position in buffer
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get total size of buffer
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Get remaining bytes from current position
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Get reference to underlying data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable reference to underlying data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Check bounds for read/write operations
    pub fn check_bounds(&self, offset: usize, length: usize) -> Result<(), MemoryError> {
        if offset.saturating_add(length) > self.data.len() {
            return Err(MemoryError::BufferOverflow {
                position: offset + length,
                size: self.data.len(),
            });
        }
        Ok(())
    }
}
