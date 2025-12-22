#[test]
fn roundtrip() {
    use std::io::{Read, Write};

    // Use in-memory buffer to avoid writing files during tests
    let cursor = std::io::Cursor::new(Vec::new());

    // Write compressed
    let mut writer = crate::lzma::writer::SegmentedLzmaWriter::new(cursor);
    writer.write_all(b"Hello World").unwrap();
    let cursor = writer.finish().unwrap(); // returns Cursor<Vec<u8>>
    let data = cursor.into_inner();

    // Read compressed from in-memory buffer
    let reader = std::io::Cursor::new(data);
    let mut reader = crate::lzma::reader::SegmentedLzmaReader::new(reader).unwrap();

    let mut decompressed = Vec::new();
    reader.read_to_end(&mut decompressed).unwrap();

    // Make sure decoded data matches
    assert_eq!(decompressed, b"Hello World");
}
