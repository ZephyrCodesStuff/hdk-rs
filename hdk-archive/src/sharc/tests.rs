#[test]
fn roundtrip_write_read() {
    use hdk_secure::hash::AfsHash;

    use crate::sharc::writer::SharcWriter;

    let test_key: [u8; 32] = [0; 32];

    let mut buf: Vec<u8> = Vec::new();
    let mut w = SharcWriter::new(&mut buf, test_key, crate::structs::Endianness::Little).unwrap();
    let file_a = b"Hello world".as_ref();
    let file_b = b"Another file!".as_ref();

    w.add_entry_from_bytes(
        AfsHash::new_from_str("file_a"),
        crate::structs::CompressionType::ZLib,
        file_a,
    )
    .unwrap();
    w.add_entry_from_bytes(
        AfsHash::new_from_str("file_b"),
        crate::structs::CompressionType::EdgeZLib,
        file_b,
    )
    .unwrap();
    w.add_entry_from_bytes(
        AfsHash::new_from_str("secret_file"),
        crate::structs::CompressionType::Encrypted,
        b"Secret",
    )
    .unwrap();

    let out = w.finish().unwrap();

    // Now open with the reader
    let cursor = std::io::Cursor::new(out);
    let archive = crate::sharc::reader::SharcReader::open(cursor, test_key).unwrap();

    assert_eq!(archive.header().file_count, 3);
}
