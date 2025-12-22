pub const EDGE_ZLIB_CHUNK_SIZE_MAX: usize = 0xFFFF;
pub const EDGE_ZLIB_CHUNK_HEADER_SIZE: usize = 4;

pub mod reader;
pub mod writer;

mod tests;
