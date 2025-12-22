use lzma_rust2::{EncodeMode, LzmaOptions, MfType};

mod segment;
mod reader;
mod writer;
mod tests;

const MAGIC: &[u8] = b"segs";
const HEADER_SIZE: usize = 16;
const SEGMENT_SIZE: usize = u16::MAX as usize + 1;

/// These parameters match the recommended ones by Sony in their
/// internal EdgeLZMA samples.
///
/// They explicitly mention that in order to be able to decompress
/// a file on the PS3's SPU, we must not exceed these limits.
const LMZA_OPTIONS: LzmaOptions = LzmaOptions {
    dict_size: 65536,
    lc: 3,
    lp: 0,
    pb: 2,
    mode: EncodeMode::Normal,
    mf: MfType::Bt4,
    nice_len: 64,
    depth_limit: 0,
    preset_dict: None,
};