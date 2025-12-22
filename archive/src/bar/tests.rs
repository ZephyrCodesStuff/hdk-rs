#[cfg(test)]
mod tests {
    use byteorder::{LittleEndian, WriteBytesExt};
    use sha1::Digest;
    use std::io::{Cursor, Read};

    use crate::{bar::BarWriter, structs::CompressionType};

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

    #[test]
    fn golden_file() {
        use crate::bar::reader::BarReader;

        let data = include_bytes!("../../COREDATA.BAR");
        let cursor = Cursor::new(data);

        let mut archive = BarReader::open(cursor).expect("Failed to open BAR");

        // Read and extract all entries under output
        std::fs::create_dir_all("output").ok();
        for i in 0..archive.entries().len() {
            let mut reader = archive.entry_reader(i).expect("Failed to get entry reader");
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .expect("Failed to read content");
            std::fs::write(format!("output/entry_{}.bin", i), content)
                .expect("Failed to write content");
        }

        // Now take all of the entries in the output directory and create a new BAR file
        let mut new_archive = BarWriter::new(Cursor::new(Vec::new()));
        for i in 0..archive.entries().len() {
            let mut reader = std::fs::File::open(format!("output/entry_{}.bin", i))
                .expect("Failed to open entry file");
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .expect("Failed to read content");
            new_archive
                .add_entry(i as i32, CompressionType::None, &content)
                .expect("Failed to add entry");
        }

        let mut new_data = new_archive.finish().expect("Failed to finish BAR");
        std::fs::write("debug_repacked.bar", new_data.get_ref())
            .expect("Failed to write debug bar");
        new_data.set_position(0);
        let mut new_archive = BarReader::open(new_data).expect("Failed to open BAR");
        assert_eq!(new_archive.entries().len(), archive.entries().len());

        // Extract the new archive in output2
        std::fs::create_dir_all("output2").ok();
        for i in 0..new_archive.entries().len() {
            let mut reader = new_archive
                .entry_reader(i)
                .expect("Failed to get entry reader");
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .expect("Failed to read content");
            std::fs::write(format!("output2/entry_{}.bin", i), content)
                .expect("Failed to write content");
        }

        // For each file, sha1 and compare
        for i in 0..archive.entries().len() {
            let mut reader = std::fs::File::open(format!("output/entry_{}.bin", i))
                .expect("Failed to open entry file");
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .expect("Failed to read content");
            let sha1 = sha1::Sha1::digest(&content);
            let mut reader = std::fs::File::open(format!("output2/entry_{}.bin", i))
                .expect("Failed to open entry file");
            let mut content = Vec::new();
            reader
                .read_to_end(&mut content)
                .expect("Failed to read content");
            let sha2 = sha1::Sha1::digest(&content);

            println!("Comparing entry {}", i);

            assert_eq!(sha1, sha2);
        }
    }
}
