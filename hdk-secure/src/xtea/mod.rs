pub mod modes;

use byteorder::{ByteOrder, LE};
use cipher::{
    BlockBackend, BlockCipher, BlockClosure, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit,
    KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U8},
    generic_array::GenericArray,
    inout::InOut,
};

#[cfg(feature = "simd")]
use std::simd::u32x64;

#[cfg(feature = "simd")]
use cipher::consts::U64;

pub const ROUNDS: usize = 16;

#[derive(Clone)]
pub struct Xtea {
    s: [u32; 4],
    s0: [u32; 16],
    s1: [u32; 16],
    subkeys: [[[u32; 16]; 2]; 8],
}

impl Xtea {
    const fn process_sub_keys(&mut self, mut sum: i32, index: i32, lookup: bool) {
        let mut j = 0;

        if lookup {
            while j < (((ROUNDS as i32) & index) >> 3) {
                sum = sum.wrapping_add(0xF1BBCDC8_u32 as i32);
                j += 1;
            }
        } else {
            while j < (((ROUNDS as i32) & index) >> 3) {
                let i = j as usize;
                let mut blocksum = sum;

                let mut k = 0;
                while k < 8 {
                    // Even subkey
                    self.subkeys[k][0][i] =
                        (blocksum as u32).wrapping_add(self.s[(blocksum as usize) & 3]);

                    // Odd subkey
                    blocksum = match k {
                        0 => sum.wrapping_add(0x9E3779B9_u32 as i32),
                        1 => sum.wrapping_add(0x3C6EF372),
                        2 => sum.wrapping_add(0xDAA66D2B_u32 as i32),
                        3 => sum.wrapping_add(0x78DDE6E4),
                        4 => sum.wrapping_add(0x1715609D),
                        5 => sum.wrapping_add(0xB54CDA56_u32 as i32),
                        6 => sum.wrapping_add(0x5384540F),
                        7 => sum.wrapping_add(0xF1BBCDC8_u32 as i32),
                        _ => blocksum,
                    };

                    self.subkeys[k][1][i] =
                        (blocksum as u32).wrapping_add(self.s[(blocksum as usize) >> 11 & 3]);
                    k += 1;
                }

                sum = sum.wrapping_add(0xF1BBCDC8_u32 as i32);
                j += 1;
            }
        }
    }

    #[inline(always)]
    fn encrypt_block_scalar(&self, block: &mut GenericArray<u8, U8>) {
        let mut v0 = LE::read_u32(&block[0..4]);
        let mut v1 = LE::read_u32(&block[4..8]);

        let mut j = 0;
        while j < 2 {
            let j_idx = j as usize;
            let mut k = 0;
            while k < 8 {
                // v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ subkey
                let v1_op = (v1 << 4 ^ v1 >> 5).wrapping_add(v1);
                v0 = v0.wrapping_add(v1_op ^ self.subkeys[k][0][j_idx]);

                // v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ subkey
                let v0_op = (v0 << 4 ^ v0 >> 5).wrapping_add(v0);
                v1 = v1.wrapping_add(v0_op ^ self.subkeys[k][1][j_idx]);

                k += 1;
            }
            j += 1;
        }

        LE::write_u32(&mut block[0..4], v0);
        LE::write_u32(&mut block[4..8], v1);
    }

    #[inline(always)]
    fn decrypt_block_scalar(&self, block: &mut GenericArray<u8, U8>) {
        let mut v0 = LE::read_u32(&block[0..4]);
        let mut v1 = LE::read_u32(&block[4..8]);

        // Reverse logic
        // j loops 0..2 normally, so go 1..=0 (descending)
        let mut j = 1;
        while j >= 0 {
            let j_idx = j as usize;
            let mut k = 7;
            while k >= 0 {
                // Reverse order of operations:
                // Encrypt: update v0 then v1.
                // Decrypt: undo v1 then v0.

                // Undo v1
                // v1 = v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ subkey)
                let v0_op = (v0 << 4 ^ v0 >> 5).wrapping_add(v0);
                v1 = v1.wrapping_sub(v0_op ^ self.subkeys[k as usize][1][j_idx]);

                // Undo v0
                // v0 = v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ subkey)
                let v1_op = (v1 << 4 ^ v1 >> 5).wrapping_add(v1);
                v0 = v0.wrapping_sub(v1_op ^ self.subkeys[k as usize][0][j_idx]);

                k -= 1;
            }
            j -= 1;
        }

        LE::write_u32(&mut block[0..4], v0);
        LE::write_u32(&mut block[4..8], v1);
    }
}

impl KeySizeUser for Xtea {
    type KeySize = cipher::consts::U16;
}

impl KeyInit for Xtea {
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let mut cipher = Self {
            s: [0; 4],
            s0: [0; 16],
            s1: [0; 16],
            subkeys: [[[0; 16]; 2]; 8],
        };

        cipher.s = [
            LE::read_u32(&key[0..4]),
            LE::read_u32(&key[4..8]),
            LE::read_u32(&key[8..12]),
            LE::read_u32(&key[12..16]),
        ];

        let mut sum = 0i32;
        let mut i = 0;
        while i < ROUNDS {
            cipher.s0[i] = (sum as u32).wrapping_add(cipher.s[(sum as usize) & 3]);
            sum = sum.wrapping_add(0x9E3779B9_u32 as i32);
            cipher.s1[i] = (sum as u32).wrapping_add(cipher.s[(sum as usize) >> 11 & 3]);
            i += 1;
        }

        let mut i = 8;
        while i <= ROUNDS {
            cipher.process_sub_keys(sum, i as i32, true);
            i += 1;
        }

        // Populate subkeys for the encryption rounds (i=2 case)
        // sum=0 (default sub_sum), index=16 (i=2 * 8), lookup=false
        cipher.process_sub_keys(0, 16, false);

        cipher
    }
}

impl BlockSizeUser for Xtea {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for Xtea {
    #[cfg(feature = "simd")]
    type ParBlocksSize = U64;
    #[cfg(not(feature = "simd"))]
    type ParBlocksSize = U1;
}

impl BlockCipher for Xtea {}

// Backend for Encryption (Forward)
impl BlockBackend for Xtea {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, GenericArray<u8, U8>>) {
        let input = block.clone_in();
        let block_ref = block.get_out();
        *block_ref = input;
        self.encrypt_block_scalar(block_ref);
    }

    #[cfg(feature = "simd")]
    #[inline]
    fn proc_par_blocks(
        &mut self,
        mut blocks: InOut<'_, '_, GenericArray<GenericArray<u8, U8>, U64>>,
    ) {
        let input = blocks.clone_in();
        let blocks_ref = blocks.get_out();
        *blocks_ref = input;

        // Arrays to gather data into - 64 lanes
        let mut buf_v0 = [0u32; 64];
        let mut buf_v1 = [0u32; 64];

        // 1. Gather
        for (i, block) in blocks_ref.iter().enumerate() {
            buf_v0[i] = LE::read_u32(&block[0..4]);
            buf_v1[i] = LE::read_u32(&block[4..8]);
        }

        // 2. Load into SIMD vectors
        let mut v0 = u32x64::from_array(buf_v0);
        let mut v1 = u32x64::from_array(buf_v1);

        // 3. Process
        let mut j = 0;
        while j < 2 {
            let j_idx = j as usize;
            let mut k = 0;
            while k < 8 {
                let sk0 = u32x64::splat(self.subkeys[k][0][j_idx]);
                let sk1 = u32x64::splat(self.subkeys[k][1][j_idx]);

                let v1_op = ((v1 << 4) ^ (v1 >> 5)) + v1;
                v0 += v1_op ^ sk0;

                let v0_op = ((v0 << 4) ^ (v0 >> 5)) + v0;
                v1 += v0_op ^ sk1;

                k += 1;
            }
            j += 1;
        }

        // 4. Scatter back
        buf_v0 = v0.to_array();
        buf_v1 = v1.to_array();

        for (i, block) in blocks_ref.iter_mut().enumerate() {
            LE::write_u32(&mut block[0..4], buf_v0[i]);
            LE::write_u32(&mut block[4..8], buf_v1[i]);
        }
    }
}

impl BlockEncrypt for Xtea {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut self.clone());
    }
}

// Backend for Decryption (Reverse)
#[derive(Clone)]
struct XteaDecBackend(Xtea);

impl BlockSizeUser for XteaDecBackend {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for XteaDecBackend {
    type ParBlocksSize = U1; // No SIMD for decrypt implemented
}

impl BlockBackend for XteaDecBackend {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, GenericArray<u8, U8>>) {
        let input = block.clone_in();
        let block_ref = block.get_out();
        *block_ref = input;
        self.0.decrypt_block_scalar(block_ref);
    }
}

impl BlockDecrypt for Xtea {
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut XteaDecBackend(self.clone()));
    }
}
