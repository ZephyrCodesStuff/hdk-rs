use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use std::io::{Read, Seek, SeekFrom, Write};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub struct SharcCryptor<R> {
    reader: R,
    cipher: Aes256Ctr,
    start_offset: u64,
}

impl<R: Seek> SharcCryptor<R> {
    pub fn new(mut reader: R, key: &[u8; 32], iv: &[u8; 16]) -> Self {
        let mut cipher = Aes256Ctr::new(key.into(), iv.into());
        cipher.seek(0); // Ensure cipher is at the start

        let start_offset = reader
            .stream_position()
            .expect("Failed to get current position for SharcCryptor");

        SharcCryptor {
            reader,
            cipher,
            start_offset,
        }
    }
}

impl<R: Read> Read for SharcCryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.cipher.apply_keystream(&mut buf[..n]);
        Ok(n)
    }
}

impl<R: Seek> Seek for SharcCryptor<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let phys_pos = match pos {
            SeekFrom::Start(n) => self.start_offset + n,
            SeekFrom::Current(n) => (self.reader.stream_position()? as i64 + n) as u64,
            SeekFrom::End(n) => (self.reader.seek(SeekFrom::End(0))? as i64 + n) as u64,
        };

        // Move the file pointer
        self.reader.seek(SeekFrom::Start(phys_pos))?;

        // Sync the cipher to the RELATIVE position (relative to where decryption started)
        let relative_pos = phys_pos.saturating_sub(self.start_offset);
        self.cipher.seek(relative_pos);

        // Return the relative pos so binrw thinks it's at 0, 4, 8, ...
        Ok(relative_pos)
    }
}

impl<R: Write> Write for SharcCryptor<R> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut encrypted = buf.to_vec();
        self.cipher.apply_keystream(&mut encrypted);
        self.reader.write(&encrypted)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.reader.flush()
    }
}
