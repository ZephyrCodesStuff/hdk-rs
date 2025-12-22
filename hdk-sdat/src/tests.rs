use std::io::Cursor;

use crate::{SdatReader, SdatStreamWriter, SdatWriter};

#[test]
fn roundtrip_writer_reader_plain() {
    let input = b"hello sdat - roundtrip test".to_vec();

    let w = SdatWriter::new("TEST.BIN").unwrap();
    let sdat_bytes = w.write_to_vec(&input).unwrap();

    let mut r = SdatReader::open(Cursor::new(sdat_bytes)).unwrap();
    let output = r.decrypt_to_vec().unwrap();

    assert_eq!(output, input);
}

#[test]
fn roundtrip_stream_writer_reader_plain() {
    let input = b"hello sdat - streaming roundtrip test".to_vec();

    let mut out = Cursor::new(Vec::<u8>::new());
    let mut in_cur = Cursor::new(input.clone());
    let (out, _bytes_written) = SdatStreamWriter::new(&mut out, "TEST_STREAM.BIN")
        .unwrap()
        .write_from_reader_seekable(&mut in_cur)
        .unwrap();

    // `out` here is &mut Cursor<Vec<u8>>; get the bytes from the original cursor.
    let sdat_bytes = out.get_ref().clone();

    let mut r = SdatReader::open(Cursor::new(sdat_bytes)).unwrap();
    let output = r.decrypt_to_vec().unwrap();

    assert_eq!(output, input);
}
