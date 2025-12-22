//! Custom `PlayStation` LZ compression/decompression
//!
//! This module implements a reverse-engineered custom Lempel-Ziv-Markov based compression
//! algorithm used by `PlayStation` systems. The algorithm uses range coding and a sliding
//! window dictionary for decompression.

use crate::error::CompressionError;

/// Range decoder state for `PlayStation` LZ decompression
struct RangeDecoder<'a> {
    range: u32,
    code: u32,
    src: &'a [u8],
    src_pos: usize,
}

impl<'a> RangeDecoder<'a> {
    /// Create a new range decoder from input data
    fn new(input: &'a [u8]) -> Result<Self, CompressionError> {
        if input.len() < 5 {
            return Err(CompressionError::InvalidFormat);
        }

        let code = (u32::from(input[1]) << 24)
            | (u32::from(input[2]) << 16)
            | (u32::from(input[3]) << 8)
            | u32::from(input[4]);

        Ok(RangeDecoder {
            range: 0xFFFFFFFF,
            code,
            src: input,
            src_pos: 5,
        })
    }

    /// Decode range - normalize range and code values
    fn decode_range(&mut self) -> Result<(), CompressionError> {
        if (self.range >> 24) == 0 {
            self.range <<= 8;
            if self.src_pos < self.src.len() {
                self.code = (self.code << 8) + u32::from(self.src[self.src_pos]);
                self.src_pos += 1;
            } else {
                return Err(CompressionError::DecompressionFailed(
                    "Unexpected end of input".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Decode a single bit using range coding
    fn decode_bit(
        &mut self,
        mut index: Option<&mut i32>,
        c: &mut u8,
    ) -> Result<bool, CompressionError> {
        self.decode_range()?;

        let val = (self.range >> 8) * u32::from(*c);
        *c -= *c >> 3;

        if let Some(ref mut idx) = index {
            **idx <<= 1;
        }

        if self.code < val {
            self.range = val;
            *c += 31;
            if let Some(ref mut idx) = index {
                **idx += 1;
            }
            Ok(true)
        } else {
            self.code -= val;
            self.range -= val;
            Ok(false)
        }
    }

    /// Decode a number using the range decoder
    fn decode_number(
        &mut self,
        ptr: &mut [u8],
        index: i32,
        bit_flag: &mut bool,
    ) -> Result<i32, CompressionError> {
        let mut i = 1i32;
        let mut idx = index;

        if idx >= 3 {
            self.decode_bit(Some(&mut i), &mut ptr[0x18])?;
            if idx >= 4 {
                self.decode_bit(Some(&mut i), &mut ptr[0x18])?;
                if idx >= 5 {
                    self.decode_range()?;
                    while idx >= 5 {
                        i <<= 1;
                        self.range >>= 1;
                        if self.code < self.range {
                            i += 1;
                        } else {
                            self.code -= self.range;
                        }
                        idx -= 1;
                    }
                }
            }
        }

        *bit_flag = self.decode_bit(Some(&mut i), &mut ptr[0])?;

        if index >= 1 {
            self.decode_bit(Some(&mut i), &mut ptr[0x8])?;
            if index >= 2 {
                self.decode_bit(Some(&mut i), &mut ptr[0x10])?;
            }
        }

        Ok(i)
    }

    /// Decode a word using the range decoder
    fn decode_word(
        &mut self,
        ptr: &mut [u8],
        index: i32,
        bit_flag: &mut bool,
    ) -> Result<i32, CompressionError> {
        let mut i = 1i32;
        let mut idx = index / 8;

        if idx >= 3 {
            self.decode_bit(Some(&mut i), &mut ptr[4])?;
            if idx >= 4 {
                self.decode_bit(Some(&mut i), &mut ptr[4])?;
                if idx >= 5 {
                    self.decode_range()?;
                    while idx >= 5 {
                        i <<= 1;
                        self.range >>= 1;
                        if self.code < self.range {
                            i += 1;
                        } else {
                            self.code -= self.range;
                        }
                        idx -= 1;
                    }
                }
            }
        }

        *bit_flag = self.decode_bit(Some(&mut i), &mut ptr[0])?;

        if index >= 1 {
            self.decode_bit(Some(&mut i), &mut ptr[1])?;
            if index >= 2 {
                self.decode_bit(Some(&mut i), &mut ptr[2])?;
            }
        }

        Ok(i)
    }
}

/// Decompress data using custom `PlayStation` LZ algorithm
pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize, CompressionError> {
    if input.is_empty() {
        return Err(CompressionError::InvalidFormat);
    }

    let head = input[0] as i8;

    // Check if we have a valid starting byte
    if head < 0 {
        // The dictionary header is invalid, the data is not compressed
        let decoder = RangeDecoder::new(input)?;
        let uncompressed_size = decoder.code as usize;

        if uncompressed_size > output.len() {
            return Err(CompressionError::DecompressionFailed(format!(
                "Output buffer too small: need {}, have {}",
                uncompressed_size,
                output.len()
            )));
        }

        if input.len() < 5 + uncompressed_size {
            return Err(CompressionError::InvalidFormat);
        }

        output[..uncompressed_size].copy_from_slice(&input[5..5 + uncompressed_size]);
        return Ok(uncompressed_size);
    }

    // Set up the range decoder
    let mut decoder = RangeDecoder::new(input)?;

    // Set up a temporary buffer (sliding window) - 0xCC8 bytes total
    let mut tmp = vec![0x80u8; 0xCC8];

    let mut offset = 0usize;
    let mut prev = 0u8;
    let mut out_pos = 0usize;

    loop {
        // Start reading at 0xB68
        let tmp_sect1_offset = offset + 0xB68;
        if tmp_sect1_offset >= tmp.len() {
            return Err(CompressionError::DecompressionFailed(
                "Buffer overflow in tmp_sect1".to_string(),
            ));
        }

        let bit = decoder.decode_bit(None, &mut tmp[tmp_sect1_offset])?;

        if bit {
            // Compressed char stream
            let mut index = -1i32;
            let mut tmp_sect1_offset = offset + 0xB68;

            // Identify the data length bit field
            loop {
                tmp_sect1_offset += 8;
                if tmp_sect1_offset >= tmp.len() {
                    return Err(CompressionError::DecompressionFailed(
                        "Buffer overflow in data length search".to_string(),
                    ));
                }

                let bit_flag = decoder.decode_bit(None, &mut tmp[tmp_sect1_offset])?;
                index += i32::from(bit_flag);

                if !bit_flag || index >= 6 {
                    break;
                }
            }

            // Default block size is 0x160
            let mut b_size = 0x160usize;
            let mut tmp_sect2_offset = (index as usize) + 0x7F1;

            let data_length =
                if index >= 0 || decoder.decode_bit(None, &mut tmp[tmp_sect1_offset])? {
                    // Locate next section
                    let sect = ((index as usize) << 5)
                        | (((out_pos << (index as usize)) & 3) << 3)
                        | (offset & 7);
                    let tmp_sect1_new_offset = 0xBA8 + sect;

                    if tmp_sect1_new_offset + 0x18 >= tmp.len() {
                        return Err(CompressionError::DecompressionFailed(
                            "Buffer overflow in tmp_sect1_new".to_string(),
                        ));
                    }

                    let mut bit_flag = false;
                    let data_len = decoder.decode_number(
                        &mut tmp[tmp_sect1_new_offset..],
                        index,
                        &mut bit_flag,
                    )?;

                    if data_len == 0xFF {
                        return Ok(out_pos); // End of stream
                    }

                    data_len
                } else {
                    1 // Assume one byte of advance
                };

            // If we got valid parameters, seek to find data offset
            if data_length <= 2 {
                tmp_sect2_offset += 0xF8;
                b_size = 0x40; // Block size is now 0x40
            }

            let mut diff: i32;
            let mut shift = 1i32;

            // Identify the data offset bit field
            loop {
                diff = (shift << 4) - (b_size as i32);
                let shift_offset = (shift as usize) << 3;
                if tmp_sect2_offset + shift_offset >= tmp.len() {
                    return Err(CompressionError::DecompressionFailed(
                        "Buffer overflow in data offset search".to_string(),
                    ));
                }

                let _bit_flag = decoder
                    .decode_bit(Some(&mut shift), &mut tmp[tmp_sect2_offset + shift_offset])?;

                if diff >= 0 {
                    break;
                }
            }

            let data_offset = if diff > 0
                || decoder.decode_bit(None, &mut tmp[tmp_sect2_offset + ((shift as usize) << 3)])?
            {
                // Adjust diff if needed
                if diff <= 0 {
                    diff -= 8;
                }

                // Locate section
                let tmp_sect3_offset = 0x928 + (diff as usize);

                if tmp_sect3_offset + 4 >= tmp.len() {
                    return Err(CompressionError::DecompressionFailed(
                        "Buffer overflow in tmp_sect3".to_string(),
                    ));
                }

                let mut bit_flag = false;
                decoder.decode_word(&mut tmp[tmp_sect3_offset..], diff, &mut bit_flag)?
            } else {
                1 // Assume one byte of advance
            };

            // Check bounds
            if data_offset as usize > out_pos {
                return Err(CompressionError::DecompressionFailed(
                    "Data offset underflow".to_string(),
                ));
            }

            let buf_start = out_pos - (data_offset as usize);
            let buf_end = out_pos + (data_length as usize) + 1;

            if buf_end > output.len() {
                return Err(CompressionError::DecompressionFailed(
                    "Output buffer overflow".to_string(),
                ));
            }

            // Update offset
            offset = ((buf_end + 1) & 1) + 6;

            // Copy data
            for i in 0..=(data_length as usize) {
                if buf_start + i >= out_pos || out_pos + i >= output.len() {
                    return Err(CompressionError::DecompressionFailed(
                        "Copy operation bounds error".to_string(),
                    ));
                }
                output[out_pos + i] = output[buf_start + i];
            }

            out_pos = buf_end;
        } else {
            // Raw char
            offset = offset.saturating_sub(1);
            if out_pos >= output.len() {
                return Ok(out_pos);
            }

            // Locate first section
            let sect = (((((out_pos & 7) << 8) + (prev as usize)) >> (head as usize)) & 7) * 0xFF;
            if sect >= tmp.len() {
                return Err(CompressionError::DecompressionFailed(
                    "Buffer overflow in sect calculation".to_string(),
                ));
            }

            let mut index = 1i32;

            // Read, decode and write back
            loop {
                let idx_val = index as usize;
                if (sect + idx_val) >= tmp.len() {
                    return Err(CompressionError::DecompressionFailed(
                        "Buffer overflow in index loop".to_string(),
                    ));
                }
                decoder.decode_bit(Some(&mut index), &mut tmp[sect + idx_val])?;
                if (index >> 8) != 0 {
                    break;
                }
            }

            // Save index
            output[out_pos] = index as u8;
            out_pos += 1;
        }

        if out_pos > 0 {
            prev = output[out_pos - 1];
        }
    }
}

/// Compress data using custom `PlayStation` LZ algorithm
/// Note: Only decompression is implemented in the original C code
pub fn compress(_input: &[u8], _output: &mut [u8]) -> Result<usize, CompressionError> {
    Err(CompressionError::CompressionFailed(
        "PlayStation LZ compression is not implemented (only decompression available)".to_string(),
    ))
}

/// Check if data appears to be compressed based on header
#[must_use] 
pub fn is_compressed(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Check if the first byte indicates compressed data (>= 0)
    (data[0] as i8) >= 0
}

/// Get the expected decompressed size from compressed data header
/// For uncompressed data (head < 0), the size is stored in bytes 1-4
pub fn get_decompressed_size(compressed_data: &[u8]) -> Result<usize, CompressionError> {
    if compressed_data.len() < 5 {
        return Err(CompressionError::InvalidFormat);
    }

    let head = compressed_data[0] as i8;

    if head < 0 {
        // Uncompressed data - size is stored in bytes 1-4
        let size = (u32::from(compressed_data[1]) << 24)
            | (u32::from(compressed_data[2]) << 16)
            | (u32::from(compressed_data[3]) << 8)
            | u32::from(compressed_data[4]);
        Ok(size as usize)
    } else {
        // Compressed data - we can't determine the size without decompressing
        Err(CompressionError::DecompressionFailed(
            "Cannot determine decompressed size for compressed data without decompressing"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    

    use super::*;
    

    #[test]
    fn test_is_compressed() {
        // Empty data should not be compressed
        assert!(!is_compressed(&[]));

        // Data with negative first byte should not be compressed
        assert!(!is_compressed(&[0x80, 0x00, 0x00, 0x00, 0x05]));

        // Data with positive first byte should be compressed
        assert!(is_compressed(&[0x01, 0x00, 0x00, 0x00, 0x05]));
    }

    #[test]
    fn test_get_decompressed_size_uncompressed() {
        // Test uncompressed data size extraction
        let data = [0x80, 0x00, 0x00, 0x00, 0x05]; // Size = 5
        assert_eq!(get_decompressed_size(&data).unwrap(), 5);

        let data = [0xFF, 0x00, 0x00, 0x01, 0x00]; // Size = 256
        assert_eq!(get_decompressed_size(&data).unwrap(), 256);
    }

    #[test]
    fn test_get_decompressed_size_compressed() {
        // Test compressed data - should return error
        let data = [0x01, 0x00, 0x00, 0x00, 0x05];
        assert!(get_decompressed_size(&data).is_err());
    }

    #[test]
    fn test_get_decompressed_size_invalid() {
        // Test invalid data (too short)
        let data = [0x80, 0x00, 0x00];
        assert!(get_decompressed_size(&data).is_err());
    }

    #[test]
    fn test_decompress_uncompressed() {
        // Test decompressing uncompressed data
        let input = [0x80, 0x00, 0x00, 0x00, 0x05, b'H', b'e', b'l', b'l', b'o'];
        let mut output = [0u8; 10];

        let result = decompress(&input, &mut output).unwrap();
        assert_eq!(result, 5);
        assert_eq!(&output[..5], b"Hello");
    }

    #[test]
    fn test_decompress_invalid_format() {
        // Test with empty input
        let mut output = [0u8; 10];
        assert!(decompress(&[], &mut output).is_err());

        // Test with input too short
        let input = [0x80, 0x00];
        assert!(decompress(&input, &mut output).is_err());
    }

    #[test]
    fn test_compress_not_implemented() {
        // Test that compression returns an error
        let input = b"Hello, World!";
        let mut output = [0u8; 100];

        let result = compress(input, &mut output);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not implemented"));
    }

    #[test]
    fn test_range_decoder_edge_cases() {
        // Test range decoder with minimal valid input
        let input = [0x01, 0x00, 0x00, 0x00, 0x00]; // Compressed format, minimal data
        let mut output = [0u8; 100];

        // For minimal/truncated compressed input we expect a graceful failure (Err)
        // rather than a panic; assert that explicitly.
        let result = decompress(&input, &mut output);
        assert!(
            result.is_err(),
            "Expected decompression to fail for minimal input, got: {result:?}"
        );
    }

    #[test]
    fn test_decompress_buffer_bounds() {
        // Test with uncompressed data that would overflow output buffer
        let input = [0x80, 0x00, 0x00, 0x00, 0x10]; // Claims 16 bytes but we'll provide smaller buffer
        let mut output = [0u8; 5]; // Only 5 bytes available

        let result = decompress(&input, &mut output);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Output buffer too small")
        );
    }
}
