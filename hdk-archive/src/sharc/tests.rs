pub const SHARC_DEFAULT_KEY: [u8; 32] = [
    0x2F, 0x5C, 0xED, 0xA6, 0x3A, 0x9A, 0x67, 0x2C, 0x03, 0x4C, 0x12, 0xE1, 0xE4, 0x25, 0xFA, 0x81,
    0x16, 0x16, 0xAE, 0x1C, 0xE6, 0x6D, 0xEB, 0x95, 0xB7, 0xE6, 0xBF, 0x21, 0x40, 0x47, 0x02, 0xDC,
];

pub const SHARC_SDAT_KEY: [u8; 32] = [
    0xF1, 0xBF, 0x6A, 0x4F, 0xBB, 0xBA, 0x5D, 0x0E, 0xD2, 0x7F, 0x41, 0x8A, 0x48, 0x88, 0xAF, 0x30,
    0x47, 0x86, 0xEC, 0xD4, 0x4E, 0x2D, 0x36, 0x46, 0x80, 0xDB, 0x4D, 0xF2, 0x22, 0x3A, 0x9F, 0x56,
];

#[test]
fn read() {
    use super::structs::SharcArchive;
    use binrw::BinRead;

    // Open file
    let data = std::fs::read("../COREDATA_LE.SHARC").unwrap();
    let data_len = data.len() as u32;
    let mut cur = std::io::BufReader::new(std::io::Cursor::new(data));

    let archive = SharcArchive::read_le_args(&mut cur, (SHARC_DEFAULT_KEY, data_len))
        .expect("Failed to read SHARC");

    // Extract all entry data to `../out`
    std::fs::create_dir_all("../out").expect("Failed to create output directory");
    for entry in &archive.entries {
        let data = archive
            .entry_data(&mut cur, entry)
            .expect("Failed to read entry data");
        std::fs::write(format!("../out/{}.bin", entry.name_hash), data)
            .expect("Failed to write entry data");
    }

    println!("Archive: {:#?}", archive);
}

#[test]
fn roundtrip() {
    use super::builder::SharcBuilder;
    use crate::structs::CompressionType;

    let builder = SharcBuilder::new(SHARC_SDAT_KEY, [0; 16]);
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
        builder.add_entry(hdk_secure::hash::AfsHash(name_hash), data, compression, iv);
    }

    builder
        .build(&mut writer, binrw::Endian::Little)
        .expect("Failed to build archive");

    let data = writer.into_inner();
    // let data_len = data.len() as u32;
    // let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));

    // let archive = SharcArchive::read_le_args(&mut reader, (SHARC_DEFAULT_KEY, data_len))
    //     .expect("Failed to read SHARC");

    // assert_eq!(archive.archive_info.version, 512);

    // Write archive to `../roundtrip_out.sharc` for inspection
    std::fs::write("../roundtrip_out.sharc", data).expect("Failed to write roundtrip output");
}
