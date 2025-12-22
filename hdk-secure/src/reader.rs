use cipher::StreamCipher;
use std::cmp;
use std::io::{self, Read};

// 8KB buffer (Aligns with 64-bit XTEA and 128-bit AES blocks perfectly)
const BUF_SIZE: usize = 8192;

pub struct CryptoReader<R, C> {
    inner: R,
    cipher: C,       // The dynamic cipher engine (XTEA, AES, etc.)
    buffer: Vec<u8>, // Intermediate buffer for SIMD efficiency
    pos: usize,
    cap: usize,
}

impl<R: Read, C: StreamCipher> CryptoReader<R, C> {
    pub fn new(inner: R, cipher: C) -> Self {
        Self {
            inner,
            cipher,
            buffer: vec![0u8; BUF_SIZE],
            pos: 0,
            cap: 0,
        }
    }
}

impl<R: Read, C: StreamCipher> Read for CryptoReader<R, C> {
    fn read(&mut self, out_buf: &mut [u8]) -> io::Result<usize> {
        // Refill buffer if empty
        if self.pos >= self.cap {
            self.pos = 0;
            self.cap = 0;

            // Greedy read to fill the buffer
            while self.cap < BUF_SIZE {
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
        let to_copy = cmp::min(remaining, out_buf.len());

        out_buf[..to_copy].copy_from_slice(&self.buffer[self.pos..self.pos + to_copy]);
        self.pos += to_copy;

        Ok(to_copy)
    }
}
