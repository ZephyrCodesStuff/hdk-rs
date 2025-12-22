use cipher::StreamCipher;
use std::io::{self, Write};

/// A writer that applies a stream cipher keystream to data before writing.
pub struct CryptoWriter<W, C> {
    inner: W,
    cipher: C,
}

impl<W: Write, C: StreamCipher> CryptoWriter<W, C> {
    /// Create a new CryptoWriter wrapping `inner` and using `cipher` to
    /// transform bytes written through it.
    pub fn new(inner: W, cipher: C) -> Self {
        Self { inner, cipher }
    }

    /// Consume this writer and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write, C: StreamCipher> Write for CryptoWriter<W, C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // We can't safely mutate the caller's buffer in-place, so copy into a
        // temporary buffer, apply keystream, then write it out.
        let mut tmp = buf.to_vec();
        self.cipher.apply_keystream(&mut tmp);
        self.inner.write_all(&tmp)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
