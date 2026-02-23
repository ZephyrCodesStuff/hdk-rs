//! WebAssembly library wrapper for the Home Development Kit (HDK).
//!
//! WARN: This crate was 100% vibe-coded. It needs EXTENSIVE testing.

use hdk_archive::structs::Endianness;

pub mod bar;
pub mod comp;
pub mod mapper;
pub mod sdat;
pub mod secure;
pub mod sharc;

/// Convenience function to convert a magic value to an Endianness enum.
pub const fn magic_to_endianess(buf: &[u8; 4]) -> Endianness {
    match buf {
        b"\xE1\x17\xEF\xAD" => Endianness::Little,
        b"\xAD\xEF\x17\xE1" => Endianness::Big,
        _ => panic!("Invalid magic value"),
    }
}
