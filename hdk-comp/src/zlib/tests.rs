#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use crate::zlib::{reader::SegmentedZlibReader, writer::SegmentedZlibWriter};

    #[test]
    fn test_roundtrip_simple() {
        let data = b"Hello, world! This is a test string for Zlib compression.";
        let mut buffer = Vec::new();

        {
            let mut writer = SegmentedZlibWriter::new(&mut buffer);
            writer.write_all(data).unwrap();
            writer.finish().unwrap();
        }

        let mut reader = SegmentedZlibReader::new(&buffer[..]);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();

        assert_eq!(data, &output[..]);
    }

    #[test]
    fn test_roundtrip_large() {
        // Create data larger than one chunk (64KB)
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let mut buffer = Vec::new();

        {
            let mut writer = SegmentedZlibWriter::new(&mut buffer);
            writer.write_all(&data).unwrap();
            writer.finish().unwrap();
        }
        
        // Verify we have multiple chunks (header overhead implies size > compressed size mostly, but let's just check validity)
        assert!(buffer.len() > 0);

        let mut reader = SegmentedZlibReader::new(&buffer[..]);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();

        assert_eq!(data, output);
    }
    
    #[test]
    fn test_empty() {
        let data = b"";
        let mut buffer = Vec::new();
        
        {
             let mut writer = SegmentedZlibWriter::new(&mut buffer);
             writer.write_all(data).unwrap();
             writer.finish().unwrap();
        }
        
        // Should be empty (no chunks)
        assert_eq!(buffer.len(), 0);
        
        let mut reader = SegmentedZlibReader::new(&buffer[..]);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        
        assert_eq!(output.len(), 0);
    }
}
