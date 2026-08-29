#![no_std]
#![cfg_attr(feature = "simd", feature(portable_simd))]

#[cfg(feature = "std")]
extern crate std;

#[cfg(test)]
extern crate alloc;



pub mod blowfish;
pub mod hash;
pub mod modes;
pub mod reader;
pub mod sceneid;
pub mod writer;
pub mod xtea;
pub mod xxtea;

#[cfg(test)]
mod tests;
