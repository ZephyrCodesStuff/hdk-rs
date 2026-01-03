use byteorder::{LittleEndian, WriteBytesExt};
use sha1::Digest;
use std::io::{Cursor, Read};

use crate::archive::ArchiveReader;

/// Test default Blowfish key (32 bytes) for encrypted file bodies.
const TEST_DEFAULT_KEY: [u8; 32] = [0xAA; 32];

/// Test signature Blowfish key (32 bytes) for encrypted file headers.
const TEST_SIGNATURE_KEY: [u8; 32] = [0xBB; 32];

// Helper to write a mock BAR file
fn create_mock_bar() -> Vec<u8> {
    let mut buffer = Vec::new();

    // Magic
    buffer
        .write_u32::<LittleEndian>(crate::structs::ARCHIVE_MAGIC)
        .unwrap();

    // Version and Flags (use `ArchiveVersion::BAR`)
    // version_and_flags = u32.  Hi=Version, Lo=Flags.
    // Version BAR (256) << 16 | Flags 0
    let version_u16: u16 = crate::structs::ArchiveVersion::BAR.into();
    let ver_flags = u32::from(version_u16) << 16;
    buffer.write_u32::<LittleEndian>(ver_flags).unwrap();

    // Priority, Timestamp (dummy)
    buffer.write_i32::<LittleEndian>(0).unwrap();
    buffer.write_i32::<LittleEndian>(12345).unwrap();

    // File Count (1)
    buffer.write_u32::<LittleEndian>(1).unwrap();

    // TOC (1 entry)
    // Entry 1
    // name_hash (dummy)
    buffer
        .write_i32::<LittleEndian>(0xBABEBEEF_u32 as i32)
        .unwrap();

    // offset_and_comp
    buffer.write_u32::<LittleEndian>(0).unwrap();

    // uncompressed_size (4)
    buffer.write_u32::<LittleEndian>(4).unwrap();
    // compressed_size (4)
    buffer.write_u32::<LittleEndian>(4).unwrap();

    // Data
    buffer.extend_from_slice(b"TEST");

    buffer
}

#[test]
fn test_open_bar() {
    use crate::bar::reader::BarReader;

    let data = create_mock_bar();
    let cursor = Cursor::new(data);

    // For unencrypted entries, the keys are not used, but we still need to provide them
    let mut archive =
        BarReader::open(cursor, TEST_DEFAULT_KEY, TEST_SIGNATURE_KEY, None).expect("Failed to open BAR");

    assert_eq!(archive.entry_count(), 1);
    let meta = archive
        .entry_metadata(0)
        .expect("Failed to get entry metadata");
    assert_eq!(meta.uncompressed_size, 4);

    let mut stream = archive.entry(0).expect("Failed to get entry stream");
    let mut content = Vec::new();
    stream
        .reader
        .read_to_end(&mut content)
        .expect("Failed to read content");

    assert_eq!(content, b"TEST");
}

#[test]
fn test_encrypted_entry_readback() {
    use byteorder::{LittleEndian, WriteBytesExt};
    use ctr::Ctr64BE;
    use ctr::cipher::KeyIvInit;
    use hdk_secure::blowfish::Blowfish;
    use sha1::Sha1;
    use std::io::Cursor;

    // Original content
    let content = b"Hello Encrypted BAR!";

    // Compress using EdgeZLib (segmented zlib writer)
    let mut seg = hdk_comp::zlib::writer::SegmentedZlibWriter::new(Vec::new());
    use std::io::Write;
    seg.write_all(content).unwrap();
    let compressed = seg.finish().unwrap();

    // SHA1 checksum of uncompressed data
    let mut hasher = Sha1::new();
    hasher.update(content);
    let checksum = hasher.finalize();

    // Head (4B fourcc + 20B sha1)
    let mut head = Vec::new();
    head.extend_from_slice(&[0u8; 4]);
    head.extend_from_slice(&checksum);

    // Sizes and IV forge (match reader::forge_iv)
    let num_files = 1u64;
    let uncomp_size = content.len() as u64;
    let comp_size = (compressed.len() + 28) as u64; // 24 head + 4 body_fourcc + body
    let offset = 0u64; // single file, starts right after TOC
    let timestamp = 0i32;

    let extended_timestamp = 0xFFFFFFFF00000000u64 | (timestamp as u64);
    let val = (uncomp_size << 0x30)
        | ((comp_size & 0xFFFF) << 0x20)
        | (((offset + 20 + (num_files * 16)) & 0x3FFFC) << 0xE)
        | (extended_timestamp & 0xFFFF);
    let iv = val.to_be_bytes();

    // Keys (match reader constants)
    type BlowfishCtr = Ctr64BE<Blowfish>;

    // Encrypt head with SIGNATURE_KEY using CryptoWriter
    let mut cw_head = hdk_secure::writer::CryptoWriter::new(
        Vec::new(),
        BlowfishCtr::new(&TEST_SIGNATURE_KEY.into(), &iv.into()),
    );
    cw_head.write_all(&head).unwrap();
    let head_enc = cw_head.into_inner();

    // Encrypt body with DEFAULT_KEY using IV + 3 via CryptoWriter
    let mut iv_as_u64 = u64::from_be_bytes(iv);
    iv_as_u64 = iv_as_u64.wrapping_add(3);
    let iv_body = iv_as_u64.to_be_bytes();

    let mut cw_body = hdk_secure::writer::CryptoWriter::new(
        Vec::new(),
        BlowfishCtr::new(&TEST_DEFAULT_KEY.into(), &iv_body.into()),
    );
    cw_body.write_all(&compressed).unwrap();
    let body_enc = cw_body.into_inner();

    // Body fourcc (4 bytes) - kept raw
    let body_fourcc = [0u8; 4];

    // Compose entry data
    let mut entry_data = Vec::new();
    entry_data.extend_from_slice(&head_enc);
    entry_data.extend_from_slice(&body_fourcc);
    entry_data.extend_from_slice(&body_enc);

    // Pad to 4 bytes
    let pad_len = (4 - (entry_data.len() % 4)) % 4;
    entry_data.extend_from_slice(&vec![0u8; pad_len]);

    // Build BAR bytes
    let mut buf = Vec::new();
    // Magic
    buf.write_u32::<LittleEndian>(crate::structs::ARCHIVE_MAGIC)
        .unwrap();
    // Version (BAR) and Flags
    let version_u16: u16 = crate::structs::ArchiveVersion::BAR.into();
    let ver_flags = u32::from(version_u16) << 16;
    buf.write_u32::<LittleEndian>(ver_flags).unwrap();
    // Priority, Timestamp
    buf.write_i32::<LittleEndian>(0).unwrap();
    buf.write_i32::<LittleEndian>(0).unwrap();
    // File Count (1)
    buf.write_u32::<LittleEndian>(1).unwrap();

    // TOC (one entry)
    buf.write_i32::<LittleEndian>(0xDEADBEEF_u32 as i32)
        .unwrap();
    let comp_val: u8 = crate::structs::CompressionType::Encrypted.into();
    let val = u32::from(comp_val);
    buf.write_u32::<LittleEndian>(val).unwrap();
    buf.write_u32::<LittleEndian>(content.len() as u32).unwrap();
    buf.write_u32::<LittleEndian>((compressed.len() + 28) as u32)
        .unwrap();

    // Data
    buf.extend_from_slice(&entry_data);

    // Open with BarReader and verify content round-trip
    let cursor = Cursor::new(buf);
    let mut archive =
        crate::bar::reader::BarReader::open(cursor, TEST_DEFAULT_KEY, TEST_SIGNATURE_KEY, None)
            .expect("Failed to open BAR");
    assert_eq!(archive.entry_count(), 1);

    let mut reader = archive.entry_reader(0).expect("Failed to get entry reader");
    let mut out = Vec::new();
    use std::io::Read;
    reader.read_to_end(&mut out).unwrap();

    assert_eq!(out, content);
}

#[test]
fn test_encrypted_entry_write_and_read() {
    use hdk_secure::hash::AfsHash;

    // Create writer, add encrypted entry, finish and read back
    use crate::bar::writer::BarWriter;
    use std::io::Cursor;

    let content = b"Roundtrip Encrypted Content";
    let mut writer = BarWriter::new(
        Cursor::new(Vec::new()),
        TEST_DEFAULT_KEY,
        TEST_SIGNATURE_KEY,
    );
    writer
        .add_entry(
            AfsHash::new_from_str("encrypted_file"),
            crate::structs::CompressionType::Encrypted,
            content,
        )
        .expect("Failed to add encrypted entry");

    let mut out = writer.finish().expect("Failed to finish writer");
    out.set_position(0);

    let mut archive =
        crate::bar::reader::BarReader::open(out, TEST_DEFAULT_KEY, TEST_SIGNATURE_KEY, None)
            .expect("Failed to open written BAR");
    let mut reader = archive.entry_reader(0).expect("Failed to get entry reader");
    let mut got = Vec::new();
    use std::io::Read;
    reader.read_to_end(&mut got).unwrap();

    assert_eq!(got, content);
}
