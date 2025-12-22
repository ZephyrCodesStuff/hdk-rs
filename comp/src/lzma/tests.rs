#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        use std::io::{Read, Write};

        let file = std::fs::File::create("output.segs").unwrap();
    
        // Write compressed
        let mut writer = crate::lzma::writer::SegmentedLzmaWriter::new(file);
        writer.write_all(b"Hello World").unwrap();
        writer.finish().unwrap();

        // Read compressed
        let reader = std::fs::File::open("output.segs").unwrap();
        let mut reader = crate::lzma::reader::SegmentedLzmaReader::new(reader).unwrap();
        
        let mut decompressed = Vec::new();
        reader.read_to_end(&mut decompressed).unwrap();
        
        // Make sure decoded data matches
        assert_eq!(decompressed, b"Hello World");
    }

    #[test]
    fn external_roundtrip() {
        use std::io::{Read, Write};

        // Decode
        let file = std::fs::File::open("compressed.segs").unwrap();
        let mut reader = crate::lzma::reader::SegmentedLzmaReader::new(file).unwrap();
        
        let mut decompressed = Vec::new();
        reader.read_to_end(&mut decompressed).unwrap();

        // Write compressed
        let file = std::fs::File::create("output.segs").unwrap();
        let mut writer = crate::lzma::writer::SegmentedLzmaWriter::new(file);
        writer.write_all(&decompressed).unwrap();
        writer.finish().unwrap();

        // Read again
        let reader = std::fs::File::open("output.segs").unwrap();
        let mut reader = crate::lzma::reader::SegmentedLzmaReader::new(reader).unwrap();
        
        let mut decompressed2 = Vec::new();
        reader.read_to_end(&mut decompressed2).unwrap();
        
        // Make sure decoded data matches
        assert_eq!(decompressed2, decompressed);
    }
}