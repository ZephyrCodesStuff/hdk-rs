use std::io::Cursor;

use crate::{SdatKeys, SdatReader, SdatStreamWriter, SdatWriter};

/// Test keys for SDAT operations.
/// In production, these would be the actual proprietary keys.
const TEST_KEYS: SdatKeys = SdatKeys {
    sdat_key: [0x01; 16],
    edat_key_0: [0x02; 16],
    edat_key_1: [0x03; 16],
    edat_hash_0: [0x04; 16],
    edat_hash_1: [0x05; 16],
    npdrm_omac_key_2: [0x06; 16],
    npdrm_omac_key_3: [0x07; 16],
};

#[test]
fn roundtrip_writer_reader_plain() {
    let input = b"hello sdat - roundtrip test".to_vec();

    let w = SdatWriter::new("TEST.BIN", TEST_KEYS).unwrap();
    let sdat_bytes = w.write_to_vec(&input).unwrap();

    let mut r = SdatReader::open(Cursor::new(sdat_bytes), &TEST_KEYS).unwrap();
    let output = r.decrypt_to_vec().unwrap();

    assert_eq!(output, input);
}

#[test]
fn roundtrip_stream_writer_reader_plain() {
    let input = b"hello sdat - streaming roundtrip test".to_vec();

    let mut out = Cursor::new(Vec::<u8>::new());
    let mut in_cur = Cursor::new(input.clone());
    let (out, _bytes_written) = SdatStreamWriter::new(&mut out, "TEST_STREAM.BIN", TEST_KEYS)
        .unwrap()
        .write_from_reader_seekable(&mut in_cur)
        .unwrap();

    // `out` here is &mut Cursor<Vec<u8>>; get the bytes from the original cursor.
    let sdat_bytes = out.get_ref().clone();

    let mut r = SdatReader::open(Cursor::new(sdat_bytes), &TEST_KEYS).unwrap();
    let output = r.decrypt_to_vec().unwrap();

    assert_eq!(output, input);
}
