pub const EDGE_ZLIB_CHUNK_SIZE_MAX: usize = 0xFFFF;
pub const EDGE_ZLIB_CHUNK_HEADER_SIZE: usize = 4;

mod reader;
mod writer;
mod tests;
