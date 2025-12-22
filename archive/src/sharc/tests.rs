#[cfg(test)]
mod tests {
    // #[test]
    // fn unpack_sharc() {
    //     // Read file data
    //     let data = std::fs::read("COREDATA.SHARC").unwrap();

    //     const DEFAULT_KEY: [u8; 32] = [
    //         0x2F, 0x5C, 0xED, 0xA6, 0x3A, 0x9A, 0x67, 0x2C, 0x03, 0x4C, 0x12, 0xE1, 0xE4, 0x25,
    //         0xFA, 0x81, 0x16, 0x16, 0xAE, 0x1C, 0xE6, 0x6D, 0xEB, 0x95, 0xB7, 0xE6, 0xBF, 0x21,
    //         0x40, 0x47, 0x02, 0xDC,
    //     ];

    //     // Create a cursor
    //     let cursor = std::io::Cursor::new(data);
    //     let mut archive = crate::sharc::reader::SharcReader::open(cursor, DEFAULT_KEY).unwrap();

    //     // Extract all files
    //     std::fs::create_dir_all("output").unwrap();

    //     for i in 0..archive.header.file_count {
    //         let mut file = archive.entry_reader(i as usize).unwrap();
    //         let mut out_path = std::path::PathBuf::from("output");
    //         out_path.push(format!("file_{:03}.bin", i));
    //         let mut out_file = std::fs::File::create(out_path).unwrap();
    //         std::io::copy(&mut file, &mut out_file).unwrap();
    //     }
    // }

    // #[test]
    // fn unpack_repack_unpack_sharc() {
    //     // Read file data
    //     let data = std::fs::read("COREDATA.SHARC").unwrap();

    //     const DEFAULT_KEY: [u8; 32] = [
    //         0x2F, 0x5C, 0xED, 0xA6, 0x3A, 0x9A, 0x67, 0x2C, 0x03, 0x4C, 0x12, 0xE1, 0xE4, 0x25,
    //         0xFA, 0x81, 0x16, 0x16, 0xAE, 0x1C, 0xE6, 0x6D, 0xEB, 0x95, 0xB7, 0xE6, 0xBF, 0x21,
    //         0x40, 0x47, 0x02, 0xDC,
    //     ];

    //     // Create a cursor
    //     let cursor = std::io::Cursor::new(data);
    //     let mut archive = crate::sharc::reader::SharcReader::open(cursor, DEFAULT_KEY).unwrap();

    //     // Repack into new archive
    //     let mut out_buf: Vec<u8> = Vec::new();
    //     {
    //         let mut writer = crate::sharc::writer::SharcWriter::new(
    //             &mut out_buf,
    //             DEFAULT_KEY,
    //             crate::structs::Endianness::Little,
    //         )
    //         .unwrap();

    //         for i in 0..archive.header.file_count {
    //             let name_hash = archive.entries().get(i as usize).unwrap().name_hash;
    //             let mut file = archive.entry_reader(i as usize).unwrap();
    //             let compression_type = CompressionType::Encrypted;

    //             writer
    //                 .add_entry_from_reader(name_hash, compression_type, &mut file)
    //                 .unwrap();
    //         }

    //         writer.finish().unwrap();
    //     }

    //     // Now reopen the new archive and verify contents
    //     let cursor = std::io::Cursor::new(out_buf);
    //     let mut new_archive = crate::sharc::reader::SharcReader::open(cursor, DEFAULT_KEY).unwrap();

    //     // Extract contents into output2
    //     std::fs::create_dir_all("output2").unwrap();
    //     for i in 0..new_archive.header.file_count {
    //         let mut file = new_archive.entry_reader(i as usize).unwrap();
    //         let mut out_path = std::path::PathBuf::from("output2");
    //         out_path.push(format!("file_{:03}.bin", i));
    //         let mut out_file = std::fs::File::create(out_path).unwrap();
    //         std::io::copy(&mut file, &mut out_file).unwrap();
    //     }

    //     assert_eq!(archive.header.file_count, new_archive.header.file_count);
    // }

    #[test]
    fn roundtrip_write_read() {
        const DEFAULT_KEY: [u8; 32] = [
            0x2F, 0x5C, 0xED, 0xA6, 0x3A, 0x9A, 0x67, 0x2C, 0x03, 0x4C, 0x12, 0xE1, 0xE4, 0x25,
            0xFA, 0x81, 0x16, 0x16, 0xAE, 0x1C, 0xE6, 0x6D, 0xEB, 0x95, 0xB7, 0xE6, 0xBF, 0x21,
            0x40, 0x47, 0x02, 0xDC,
        ];

        use crate::sharc::writer::SharcWriter;

        let mut buf: Vec<u8> = Vec::new();
        let mut w =
            SharcWriter::new(&mut buf, DEFAULT_KEY, crate::structs::Endianness::Little).unwrap();

        let file_a = b"Hello world".as_ref();
        let file_b = b"Another file!".as_ref();

        w.add_entry_from_bytes(0x1234_5678, crate::structs::CompressionType::ZLib, file_a)
            .unwrap();
        w.add_entry_from_bytes(
            0xDEAD_BEEF,
            crate::structs::CompressionType::EdgeZLib,
            file_b,
        )
        .unwrap();
        w.add_entry_from_bytes(
            0xA2A2_A2A2,
            crate::structs::CompressionType::Encrypted,
            b"Secret",
        )
        .unwrap();

        let out = w.finish().unwrap();

        // Now open with the reader
        let cursor = std::io::Cursor::new(out);
        let archive = crate::sharc::reader::SharcReader::open(cursor, DEFAULT_KEY).unwrap();

        assert_eq!(archive.header.file_count, 3);
    }
}
