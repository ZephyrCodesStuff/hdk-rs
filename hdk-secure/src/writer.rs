use cipher::StreamCipher;
use std::io::{self, Write};

const DEFAULT_CAPACITY: usize = 4096;

/// A writer that applies a stream cipher keystream to data before writing.
pub struct CryptoWriter<W, C> {
    inner: W,
    cipher: C,
    buf: Vec<u8>,
}

impl<W: Write, C: StreamCipher> CryptoWriter<W, C> {
    /// Create a new `CryptoWriter` wrapping `inner` and using `cipher` to
    /// transform bytes written through it.
    ///
    /// Uses a sensible default internal buffer capacity and delegates
    /// to `with_capacity`.
    pub fn new(inner: W, cipher: C) -> Self {
        Self::with_capacity(inner, cipher, DEFAULT_CAPACITY)
    }

    /// Create a new `CryptoWriter` preallocating `initial_capacity` bytes for the
    /// internal buffer. This can improve performance when the expected write
    /// sizes are known in advance.
    pub fn with_capacity(inner: W, cipher: C, initial_capacity: usize) -> Self {
        Self {
            inner,
            cipher,
            buf: Vec::with_capacity(initial_capacity),
        }
    }

    /// Consume this writer and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write, C: StreamCipher> Write for CryptoWriter<W, C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Reuse internal buffer to avoid per-write allocations.
        self.buf.clear();
        self.buf.reserve(buf.len());
        self.buf.extend_from_slice(buf);

        // Apply keystream in-place
        self.cipher.apply_keystream(&mut self.buf);

        // Write transformed data to inner writer
        self.inner.write_all(&self.buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
