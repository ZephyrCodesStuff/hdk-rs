use std::io::{Read, Seek};

use binrw::BinRead;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::sharc_new::structs::SharcArchive;

pub const SHARC_DEFAULT_KEY: [u8; 32] = [
    0x2F, 0x5C, 0xED, 0xA6, 0x3A, 0x9A, 0x67, 0x2C, 0x03, 0x4C, 0x12, 0xE1, 0xE4, 0x25, 0xFA, 0x81,
    0x16, 0x16, 0xAE, 0x1C, 0xE6, 0x6D, 0xEB, 0x95, 0xB7, 0xE6, 0xBF, 0x21, 0x40, 0x47, 0x02, 0xDC,
];

pub const SHARC_SDAT_KEY: [u8; 32] = [
    0xF1, 0xBF, 0x6A, 0x4F, 0xBB, 0xBA, 0x5D, 0x0E, 0xD2, 0x7F, 0x41, 0x8A, 0x48, 0x88, 0xAF, 0x30,
    0x47, 0x86, 0xEC, 0xD4, 0x4E, 0x2D, 0x36, 0x46, 0x80, 0xDB, 0x4D, 0xF2, 0x22, 0x3A, 0x9F, 0x56,
];

#[test]
fn aes_256() {
    // Get 28..52 of the archive
    let data = std::fs::read("../COREDATA_BE.SHARC").unwrap();
    let mut cur = std::io::Cursor::new(data);
    cur.seek(std::io::SeekFrom::Start(24)).unwrap();
    let mut encrypted = [0u8; 28];
    cur.read_exact(&mut encrypted).unwrap();

    // IV is from 8..24
    let mut iv = [0u8; 16];
    cur.seek(std::io::SeekFrom::Start(8)).unwrap();
    cur.read_exact(&mut iv).unwrap();

    ctr::Ctr128BE::<aes::Aes256>::new(&SHARC_DEFAULT_KEY.into(), &iv.into())
        .apply_keystream(&mut encrypted);

    println!("Decrypted Header: {:02X?}", encrypted);
}

#[test]
fn read_le() {
    // Open file
    let data = std::fs::read("../COREDATA_LE.SHARC").unwrap();
    let data_len = data.len() as u32;

    let mut cur = std::io::BufReader::new(std::io::Cursor::new(data));

    let archive = SharcArchive::read_le_args(&mut cur, (SHARC_DEFAULT_KEY, data_len))
        .expect("Failed to read SHARC LE");

    println!("Archive: {:#?}", archive);
}

#[test]
fn read_be() {
    // Open file
    let data = std::fs::read("../COREDATA_BE.SHARC").unwrap();
    let data_len = data.len() as u32;
    let mut cur = std::io::BufReader::new(std::io::Cursor::new(data));

    let archive = SharcArchive::read_be_args(&mut cur, (SHARC_DEFAULT_KEY, data_len))
        .expect("Failed to read SHARC BE");

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
