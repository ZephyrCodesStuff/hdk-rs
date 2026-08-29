use binrw::io::{self, Write};
use cipher::StreamCipher;

pub const DEFAULT_CHUNK_SIZE: usize = 1024;

/// A writer that applies a stream cipher keystream to data before writing.
///
/// The internal chunk size used for streaming keystream application is parameterized by `N` (defaults to 1024 bytes).
pub struct CryptoWriter<W, C, const N: usize = DEFAULT_CHUNK_SIZE> {
    inner: W,
    cipher: C,
}

impl<W: Write, C: StreamCipher> CryptoWriter<W, C, DEFAULT_CHUNK_SIZE> {
    /// Create a new `CryptoWriter` wrapping `inner` and using `cipher` with the default 1KB chunk size.
    pub const fn new(inner: W, cipher: C) -> Self {
        Self::with_chunk_size(inner, cipher)
    }

    /// Create a new `CryptoWriter`. The `_initial_capacity` parameter is ignored
    /// as data is processed in stack-allocated chunks without heap allocation.
    pub const fn with_capacity(inner: W, cipher: C, _initial_capacity: usize) -> Self {
        Self::new(inner, cipher)
    }
}

impl<W: Write, C: StreamCipher, const N: usize> CryptoWriter<W, C, N> {
    /// Create a new `CryptoWriter` with a custom chunk size `N`.
    pub const fn with_chunk_size(inner: W, cipher: C) -> Self {
        Self { inner, cipher }
    }

    /// Consume this writer and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write, C: StreamCipher, const N: usize> Write for CryptoWriter<W, C, N> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut chunk_buf = [0u8; N];
        for chunk in buf.chunks(N) {
            chunk_buf[..chunk.len()].copy_from_slice(chunk);
            self.cipher.apply_keystream(&mut chunk_buf[..chunk.len()]);
            self.inner.write_all(&chunk_buf[..chunk.len()])?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}


