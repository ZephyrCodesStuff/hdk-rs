pub mod reader;
pub mod structs;
pub mod writer;

fn to_arr16(slice: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&slice[..16]);
    a
}
