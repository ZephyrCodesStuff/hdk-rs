use binrw::io::{self, Read};
use cipher::StreamCipher;

pub const DEFAULT_BUF_SIZE: usize = 8192;

/// A reader that decrypts data on the fly from an inner reader using a stream cipher.
///
/// The internal buffer size is parameterized by the const generic `N` (defaults to 8192 bytes).
pub struct CryptoReader<R, C, const N: usize = DEFAULT_BUF_SIZE> {
    inner: R,
    cipher: C,              // The dynamic cipher engine (XTEA, AES, etc.)
    buffer: [u8; N],        // Intermediate buffer for SIMD/block efficiency
    pos: usize,
    cap: usize,
}

impl<R: Read, C: StreamCipher> CryptoReader<R, C, DEFAULT_BUF_SIZE> {
    /// Create a new `CryptoReader` with the default 8KB buffer size.
    pub fn new(inner: R, cipher: C) -> Self {
        Self::with_buf_size(inner, cipher)
    }
}

impl<R: Read, C: StreamCipher, const N: usize> CryptoReader<R, C, N> {
    /// Create a new `CryptoReader` with a custom buffer size `N`.
    pub fn with_buf_size(inner: R, cipher: C) -> Self {
        Self {
            inner,
            cipher,
            buffer: [0u8; N],
            pos: 0,
            cap: 0,
        }
    }

    /// Consume this reader and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read, C: StreamCipher, const N: usize> Read for CryptoReader<R, C, N> {
    fn read(&mut self, out_buf: &mut [u8]) -> io::Result<usize> {
        // Refill buffer if empty
        if self.pos >= self.cap {
            self.pos = 0;
            self.cap = 0;

            // Greedy read to fill the buffer
            while self.cap < N {
                let n = self.inner.read(&mut self.buffer[self.cap..])?;
                if n == 0 {
                    break;
                }
                self.cap += n;
            }

            if self.cap == 0 {
                return Ok(0);
            }

            // Apply keystream (this is where the magic happens)
            self.cipher.apply_keystream(&mut self.buffer[..self.cap]);
        }

        // Copy to output
        let remaining = self.cap - self.pos;
        let to_copy = core::cmp::min(remaining, out_buf.len());

        out_buf[..to_copy].copy_from_slice(&self.buffer[self.pos..self.pos + to_copy]);
        self.pos += to_copy;

        Ok(to_copy)
    }
}

