#![cfg_attr(feature = "simd", feature(portable_simd))]

pub mod blowfish;
pub mod modes;
pub mod xtea;

#[cfg(test)]
mod tests;
