#[cfg(test)]
mod tests {
    use byteorder::{LittleEndian, WriteBytesExt};
    use sha1::Digest;
    use std::io::{Cursor, Read};

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
        let ver_flags = ((version_u16 as u32) << 16) | 0u32;
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

        let mut archive = BarReader::open(cursor).expect("Failed to open BAR");

        assert_eq!(archive.entries().len(), 1);
        let entry = &archive.entries()[0];
        assert_eq!(entry.uncompressed_size, 4);

        let mut reader = archive.entry_reader(0).expect("Failed to get entry reader");
        let mut content = Vec::new();
        reader
            .read_to_end(&mut content)
            .expect("Failed to read content");

        assert_eq!(content, b"TEST");
    }

    // #[test]
    // fn golden_file() {
    //     use crate::bar::reader::BarReader;

    //     let data = include_bytes!("../../../COREDATA.BAR");
    //     let cursor = Cursor::new(data);

    //     let mut archive = BarReader::open(cursor).expect("Failed to open BAR");

    //     // Read and extract all entries under output
    //     std::fs::create_dir_all("output").ok();
    //     for i in 0..archive.entries().len() {
    //         let mut reader = archive.entry_reader(i).expect("Failed to get entry reader");
    //         let mut content = Vec::new();
    //         reader
    //             .read_to_end(&mut content)
    //             .expect("Failed to read content");
    //         std::fs::write(format!("output/entry_{}.bin", i), content)
    //             .expect("Failed to write content");
    //     }

    //     // Now take all of the entries in the output directory and create a new BAR file
    //     let mut new_archive = BarWriter::new(Cursor::new(Vec::new()));
    //     for i in 0..archive.entries().len() {
    //         let mut reader = std::fs::File::open(format!("output/entry_{}.bin", i))
    //             .expect("Failed to open entry file");
    //         let mut content = Vec::new();
    //         reader
    //             .read_to_end(&mut content)
    //             .expect("Failed to read content");
    //         new_archive
    //             .add_entry(i as i32, CompressionType::Encrypted, &content)
    //             .expect("Failed to add entry");
    //     }

    //     let mut new_data = new_archive.finish().expect("Failed to finish BAR");
    //     std::fs::write("debug_repacked.bar", new_data.get_ref())
    //         .expect("Failed to write debug bar");
    //     new_data.set_position(0);
    //     let mut new_archive = BarReader::open(new_data).expect("Failed to open BAR");
    //     assert_eq!(new_archive.entries().len(), archive.entries().len());

    //     // Extract the new archive in output2
    //     std::fs::create_dir_all("output2").ok();
    //     for i in 0..new_archive.entries().len() {
    //         let mut reader = new_archive
    //             .entry_reader(i)
    //             .expect("Failed to get entry reader");
    //         let mut content = Vec::new();
    //         reader
    //             .read_to_end(&mut content)
    //             .expect("Failed to read content");
    //         std::fs::write(format!("output2/entry_{}.bin", i), content)
    //             .expect("Failed to write content");
    //     }

    //     // For each file, sha1 and compare
    //     for i in 0..archive.entries().len() {
    //         let mut reader = std::fs::File::open(format!("output/entry_{}.bin", i))
    //             .expect("Failed to open entry file");
    //         let mut content = Vec::new();
    //         reader
    //             .read_to_end(&mut content)
    //             .expect("Failed to read content");
    //         let sha1 = sha1::Sha1::digest(&content);
    //         let mut reader = std::fs::File::open(format!("output2/entry_{}.bin", i))
    //             .expect("Failed to open entry file");
    //         let mut content = Vec::new();
    //         reader
    //             .read_to_end(&mut content)
    //             .expect("Failed to read content");
    //         let sha2 = sha1::Sha1::digest(&content);

    //         println!("Comparing entry {}", i);

    //         assert_eq!(sha1, sha2);
    //     }
    // }

    #[test]
    fn test_encrypted_entry_readback() {
        use byteorder::{LittleEndian, WriteBytesExt};
        use ctr::Ctr64BE;
        use ctr::cipher::KeyIvInit;
        use secure::blowfish::Blowfish;
        use sha1::Sha1;
        use std::io::Cursor;

        // Original content
        let content = b"Hello Encrypted BAR!";

        // Compress using EdgeZLib (segmented zlib writer)
        let mut seg = comp::zlib::writer::SegmentedZlibWriter::new(Vec::new());
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
        const DEFAULT_KEY: [u8; 32] = [
            0x80, 0x6D, 0x79, 0x16, 0x23, 0x42, 0xA1, 0x0E, 0x8F, 0x78, 0x14, 0xD4, 0xF9, 0x94,
            0xA2, 0xD1, 0x74, 0x13, 0xFC, 0xA8, 0xF6, 0xE0, 0xB8, 0xA4, 0xED, 0xB9, 0xDC, 0x32,
            0x7F, 0x8B, 0xA7, 0x11,
        ];

        const SIGNATURE_KEY: [u8; 32] = [
            0xEF, 0x8C, 0x7D, 0xE8, 0xE5, 0xD5, 0xD6, 0x1D, 0x6A, 0xAA, 0x5A, 0xCA, 0xF7, 0xC1,
            0x6F, 0xC4, 0x5A, 0xFC, 0x59, 0xE4, 0x8F, 0xE6, 0xC5, 0x93, 0x7E, 0xBD, 0xFF, 0xC1,
            0xE3, 0x99, 0x9E, 0x62,
        ];

        type BlowfishCtr = Ctr64BE<Blowfish>;

        // Encrypt head with SIGNATURE_KEY using CryptoWriter
        let mut cw_head = secure::writer::CryptoWriter::new(
            Vec::new(),
            BlowfishCtr::new(&SIGNATURE_KEY.into(), &iv.into()),
        );
        cw_head.write_all(&head).unwrap();
        let head_enc = cw_head.into_inner();

        // Encrypt body with DEFAULT_KEY using IV + 3 via CryptoWriter
        let mut iv_as_u64 = u64::from_be_bytes(iv);
        iv_as_u64 = iv_as_u64.wrapping_add(3);
        let iv_body = iv_as_u64.to_be_bytes();

        let mut cw_body = secure::writer::CryptoWriter::new(
            Vec::new(),
            BlowfishCtr::new(&DEFAULT_KEY.into(), &iv_body.into()),
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
        let ver_flags = ((version_u16 as u32) << 16) | 0u32;
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
        let val = (0u32 & 0xFFFFFFFC) | (comp_val as u32);
        buf.write_u32::<LittleEndian>(val).unwrap();
        buf.write_u32::<LittleEndian>(content.len() as u32).unwrap();
        buf.write_u32::<LittleEndian>((compressed.len() + 28) as u32)
            .unwrap();

        // Data
        buf.extend_from_slice(&entry_data);

        // Open with BarReader and verify content round-trip
        let cursor = Cursor::new(buf);
        let mut archive = crate::bar::reader::BarReader::open(cursor).expect("Failed to open BAR");
        assert_eq!(archive.entries().len(), 1);

        let mut reader = archive.entry_reader(0).expect("Failed to get entry reader");
        let mut out = Vec::new();
        use std::io::Read;
        reader.read_to_end(&mut out).unwrap();

        assert_eq!(out, content);
    }

    #[test]
    fn test_encrypted_entry_write_and_read() {
        // Create writer, add encrypted entry, finish and read back
        use crate::bar::writer::BarWriter;
        use std::io::Cursor;

        let content = b"Roundtrip Encrypted Content";
        let mut writer = BarWriter::new(Cursor::new(Vec::new()));
        writer
            .add_entry(
                0xCAFEBABE_u32 as i32,
                crate::structs::CompressionType::Encrypted,
                content,
            )
            .expect("Failed to add encrypted entry");

        let mut out = writer.finish().expect("Failed to finish writer");
        out.set_position(0);

        let mut archive =
            crate::bar::reader::BarReader::open(out).expect("Failed to open written BAR");
        let mut reader = archive.entry_reader(0).expect("Failed to get entry reader");
        let mut got = Vec::new();
        use std::io::Read;
        reader.read_to_end(&mut got).unwrap();

        assert_eq!(got, content);
    }
}
