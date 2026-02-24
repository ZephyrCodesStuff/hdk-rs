use binrw::{BinRead, Endian};
use criterion::{Criterion, criterion_group, criterion_main};
use hdk_archive::sharc::{builder::SharcBuilder, structs::SharcArchive};
use std::hint::black_box;

fn repack_roundtrip(c: &mut Criterion) {
    c.bench_function("unpack repack coredata sharc", |b| {
        b.iter(|| {
            let sharc_bytes = include_bytes!("../test-data/coredata.sharc");

            let mut reader = std::io::Cursor::new(sharc_bytes);
            let key = [
                0x2F, 0x5C, 0xED, 0xA6, 0x3A, 0x9A, 0x67, 0x2C, 0x03, 0x4C, 0x12, 0xE1, 0xE4, 0x25,
                0xFA, 0x81, 0x16, 0x16, 0xAE, 0x1C, 0xE6, 0x6D, 0xEB, 0x95, 0xB7, 0xE6, 0xBF, 0x21,
                0x40, 0x47, 0x02, 0xDC,
            ];
            let sharc = SharcArchive::read_be_args(&mut reader, (key, sharc_bytes.len() as u32))
                .expect("Failed to read SHARC archive");

            // extract every entry to memory
            let mut extracted_entries = Vec::new();
            for entry in &sharc.entries {
                let data = sharc
                    .entry_data(&mut reader, entry)
                    .expect("Failed to read entry data");

                extracted_entries.push((entry.name_hash, data));
            }

            // repack every entry into a new archive
            let mut repack_buf = Vec::new();
            {
                let mut writer = std::io::Cursor::new(&mut repack_buf);
                let mut builder = SharcBuilder::new(key, [0u8; 16]);

                for (name_hash, data) in extracted_entries {
                    builder.add_entry(
                        name_hash,
                        data,
                        hdk_archive::structs::CompressionType::ZLib,
                        [0u8; 8],
                    );
                }

                builder
                    .build(&mut writer, Endian::Big)
                    .expect("Failed to finish SHARC archive");
            }

            black_box(repack_buf);
        })
    });
}

criterion_group!(benches, repack_roundtrip);
criterion_main!(benches);
