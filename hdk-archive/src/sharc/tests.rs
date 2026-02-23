#[test]
fn read() {
    use super::structs::SharcArchive;
    use binrw::BinRead;

    // Open file
    let data = std::fs::read("../COREDATA_LE.SHARC").unwrap();
    let data_len = data.len() as u32;
    let mut cur = std::io::BufReader::new(std::io::Cursor::new(data));

    let archive =
        SharcArchive::read_le_args(&mut cur, ([0u8; 32], data_len)).expect("Failed to read SHARC");

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

    let builder = SharcBuilder::new([0u8; 32], [0u8; 16]);
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
