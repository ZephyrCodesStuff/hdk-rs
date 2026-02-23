use std::io::{Read, Seek};

use binrw::BinRead;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::sharc_new::structs::SharcArchive;

pub const SHARC_DEFAULT_KEY: [u8; 32] = [
    0x2F, 0x5C, 0xED, 0xA6, 0x3A, 0x9A, 0x67, 0x2C, 0x03, 0x4C, 0x12, 0xE1, 0xE4, 0x25, 0xFA, 0x81,
    0x16, 0x16, 0xAE, 0x1C, 0xE6, 0x6D, 0xEB, 0x95, 0xB7, 0xE6, 0xBF, 0x21, 0x40, 0x47, 0x02, 0xDC,
];

#[test]
fn read() {
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
        std::fs::write(format!("../out/{}.bin", entry.name_hash.abs()), data)
            .expect("Failed to write entry data");
    }

    println!("Archive: {:#?}", archive);
}
