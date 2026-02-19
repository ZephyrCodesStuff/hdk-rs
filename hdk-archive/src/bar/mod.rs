pub use reader::BarReader;
pub use structs::{BarEntry, BarEntryMetadata, BarHeader};
pub use writer::BarWriter;

pub mod reader;
pub mod structs;
pub mod writer;

#[cfg(test)]
mod tests;

/// Forge an IV for BAR encryption based on the given parameters
pub const fn forge_iv(
    num_files: u64,
    uncomp_size: u64,
    comp_size: u64,
    offset: u64,
    timestamp: i32,
) -> [u8; 8] {
    let extended_timestamp = 0xFFFFFFFF00000000u64 | (timestamp as u64);
    let val = (uncomp_size << 0x30)
        | ((comp_size & 0xFFFF) << 0x20)
        | (((offset + 20 + (num_files * 16)) & 0x3FFFC) << 0xE)
        | (extended_timestamp & 0xFFFF);
    val.to_be_bytes()
}
