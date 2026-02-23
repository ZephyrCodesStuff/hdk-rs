/// DEFAULT key used to encrypt BAR file bodies.
/// Used in BAR archives.
pub const BAR_DEFAULT_KEY: [u8; 32] = [
    0x80, 0x6D, 0x79, 0x16, 0x23, 0x42, 0xA1, 0x0E, 0x8F, 0x78, 0x14, 0xD4, 0xF9, 0x94, 0xA2, 0xD1,
    0x74, 0x13, 0xFC, 0xA8, 0xF6, 0xE0, 0xB8, 0xA4, 0xED, 0xB9, 0xDC, 0x32, 0x7F, 0x8B, 0xA7, 0x11,
];

/// Signature key used to encrypt BAR file head/signature area.
/// Used in BAR archives.
pub const BAR_SIGNATURE_KEY: [u8; 32] = [
    0xEF, 0x8C, 0x7D, 0xE8, 0xE5, 0xD5, 0xD6, 0x1D, 0x6A, 0xAA, 0x5A, 0xCA, 0xF7, 0xC1, 0x6F, 0xC4,
    0x5A, 0xFC, 0x59, 0xE4, 0x8F, 0xE6, 0xC5, 0x93, 0x7E, 0xBD, 0xFF, 0xC1, 0xE3, 0x99, 0x9E, 0x62,
];

#[test]
fn read() {
    use super::structs::BarArchive;
    use binrw::BinRead;

    // Open file
    let data = std::fs::read("../test.bar").unwrap();
    let data_len = data.len() as u32;
    let mut cur = std::io::BufReader::new(std::io::Cursor::new(data));

    let archive =
        BarArchive::read_le_args(&mut cur, (BAR_DEFAULT_KEY, BAR_SIGNATURE_KEY, data_len))
            .expect("Failed to read BAR");
    println!("Archive: {:#?}", archive);

    // Extract all entry data to `../out`
    std::fs::create_dir_all("../out").expect("Failed to create output directory");
    for entry in &archive.entries {
        let data = archive
            .entry_data(&mut cur, entry, &BAR_DEFAULT_KEY, &BAR_SIGNATURE_KEY)
            .expect("Failed to read entry data");

        std::fs::write(format!("../out/{}.bin", entry.name_hash), data)
            .expect("Failed to write entry data");
    }
}

#[test]
fn roundtrip() {
    use super::builder::BarBuilder;
    use crate::structs::CompressionType;

    let builder = BarBuilder::new(BAR_DEFAULT_KEY, BAR_SIGNATURE_KEY);
    let mut builder = builder.with_priority(123).with_timestamp(456);

    let mut buf = Vec::new();
    let mut writer = std::io::Cursor::new(&mut buf);

    let mut iv = [0u8; 8];
    let mut rng = rand::rng();
    rand::Rng::fill(&mut rng, &mut iv);

    for i in 0..4 {
        let name_hash = i + 1;
        let data = format!("Hello world {}", i).into_bytes();
        let compression = match i {
            0 => CompressionType::None,
            1 => CompressionType::ZLib,
            2 => CompressionType::EdgeZLib,
            3 => CompressionType::Encrypted,
            _ => unreachable!(),
        };
        builder.add_entry(hdk_secure::hash::AfsHash(name_hash), data, compression);
    }

    builder
        .build(&mut writer, binrw::Endian::Little)
        .expect("Failed to build archive");

    let data = writer.into_inner();
    // let data_len = data.len() as u32;
    // let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));

    // let archive = BarArchive::read_le_args(&mut reader, (BAR_DEFAULT_KEY, BAR_SIGNATURE_KEY, data.len() as u32))
    //     .expect("Failed to read BAR");

    // assert_eq!(archive.archive_info.version, 256);

    // Write archive to `../roundtrip_out.bar` for inspection
    std::fs::write("../roundtrip_out.bar", data).expect("Failed to write roundtrip output");
}
