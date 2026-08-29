use core::fmt::{self, Display};

use uuid::Uuid;

/// A SceneID as used in PlayStation Home, with methods to create, verify, and forge IDs.
///
/// This is pretty much a normal UUIDv4, but with the last two bytes being a CRC16 checksum
/// of the first 14 bytes.
///
/// Additionally, there is an obfuscation step using XOR and a scatter table to derive a 16-bit
/// SceneID from the UUID bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SceneID {
    pub src_bytes: [u8; 14],
    pub crc16: u16,

    pub final_id: Uuid,
}

#[derive(Debug)]
pub enum SceneIDError {
    InvalidUUID,
    InvalidCRC16,
}

#[cfg(feature = "std")]
impl Default for SceneID {
    fn default() -> Self {
        Self::new()
    }
}

/// Scatter table used in Home's SceneID algorithm
const SCATTER_TABLE: [[u8; 2]; 16] = [
    [3, 12],
    [8, 6],
    [2, 8],
    [4, 5],
    [5, 1],
    [4, 10],
    [1, 3],
    [11, 5],
    [3, 4],
    [5, 6],
    [13, 10],
    [7, 5],
    [2, 9],
    [3, 9],
    [10, 8],
    [4, 10],
];

/// XOR mask used in Home's SceneID algorithm
const UUID_XOR: [u8; 16] = [
    0xB9, 0x20, 0x86, 0xBC, 0x3E, 0x8B, 0x4A, 0xDF, 0xA3, 0x01, 0x4D, 0xEE, 0x2F, 0xA3, 0xAB, 0x69,
];

impl SceneID {
    /// Creates a new random SceneID using the thread RNG (requires `std`).
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        Self::new_with_rng(&mut rand::rng())
    }

    /// Creates a new random SceneID using the provided random number generator.
    pub fn new_with_rng<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 14];
        rng.fill(&mut bytes);

        let mut crc16 = crc16::State::<crc16::AUG_CCITT>::new();
        crc16.update(&bytes);

        let mut final_uuid = [0u8; 16];
        final_uuid[0..14].copy_from_slice(&bytes);
        final_uuid[14..16].copy_from_slice(&crc16.get().to_le_bytes());

        Self {
            src_bytes: bytes,
            crc16: crc16.get(),
            final_id: Uuid::from_slice(&final_uuid).unwrap(),
        }
    }

    /// Extracts the SceneID u16 from the UUID, using Home's algorithm.
    pub fn extract_scene_id(&self) -> u16 {
        let mut xor_bytes = [0u8; 16];

        for (i, (a, b)) in self.final_id.as_bytes().iter().zip(UUID_XOR).enumerate() {
            xor_bytes[i] = a ^ b;
        }

        let index = (xor_bytes[0] & 15) as usize;
        xor_bytes[SCATTER_TABLE[index][0] as usize] as u16
            | ((xor_bytes[SCATTER_TABLE[index][1] as usize] as u16) << 8)
    }

    /// Validates a SceneID from raw bytes, using Home's algorithm.
    ///
    /// # Errors
    /// Returns an error if the UUID is invalid or the CRC16 does not match.
    pub fn verify(bytes: &[u8; 16]) -> Result<Self, SceneIDError> {
        let uuid = Uuid::from_slice(bytes).map_err(|_| SceneIDError::InvalidUUID)?;
        let id_bytes: &[u8; 14] = &uuid.as_bytes()[0..14].try_into().unwrap();
        let given_crc = u16::from_le_bytes(bytes[14..16].try_into().unwrap());

        let mut calculated_crc = crc16::State::<crc16::AUG_CCITT>::new();
        calculated_crc.update(id_bytes);

        if given_crc != calculated_crc.get() {
            return Err(SceneIDError::InvalidCRC16);
        }

        Ok(Self {
            src_bytes: *id_bytes,
            crc16: given_crc,

            final_id: uuid,
        })
    }

    /// Convenience to verify from a string representation of the UUID.
    ///
    /// Avoids the caller needing to parse the UUID separately with the crate.
    pub fn verify_str(string: &str) -> Result<Self, SceneIDError> {
        let uuid = Uuid::parse_str(string).map_err(|_| SceneIDError::InvalidUUID)?;
        Self::verify(uuid.as_bytes())
    }

    /// Forges a SceneID that maps to the given target u16 using the thread RNG (requires `std`).
    /// If target_crc is None, a random valid CRC16 will be generated.
    #[cfg(feature = "std")]
    pub fn forge(target: u16, target_crc: Option<u16>) -> Self {
        Self::forge_with_rng(target, target_crc, &mut rand::rng())
    }

    /// Forges a SceneID that maps to the given target u16 using the provided random number generator.
    /// If target_crc is None, a random valid CRC16 will be generated.
    pub fn forge_with_rng<R: rand::Rng + ?Sized>(
        target: u16,
        target_crc: Option<u16>,
        rng: &mut R,
    ) -> Self {
        let target_byte1 = (target & 0xFF) as u8;

        let target_byte2 = ((target >> 8) & 0xFF) as u8;

        // Try to find an index where we can control the CRC positions if needed
        let mut chosen_index = None;
        let target_crc = target_crc.unwrap_or_else(|| rng.random::<u16>());

        // First, try indices where both positions are in the 14-byte range (easier)
        for (index, table_i) in SCATTER_TABLE.iter().enumerate() {
            let pos1 = table_i[0] as usize;
            let pos2 = table_i[1] as usize;

            if pos1 < 14 && pos2 < 14 {
                chosen_index = Some(index);
                break;
            }
        }

        let chosen_index = chosen_index.unwrap_or(0);
        let pos1 = SCATTER_TABLE[chosen_index][0] as usize;
        let pos2 = SCATTER_TABLE[chosen_index][1] as usize;

        // Generate random UUID bytes
        let mut uuid_bytes = [0u8; 14];
        rng.fill(&mut uuid_bytes);

        // Set first byte to get our chosen index
        let random_upper = rng.random::<u8>() & 0xF0;
        let desired_xor_first = chosen_index as u8 | random_upper;
        uuid_bytes[0] = desired_xor_first ^ UUID_XOR[0];

        // Handle positions that are in the 14-byte range
        if pos1 < 14 {
            uuid_bytes[pos1] = target_byte1 ^ UUID_XOR[pos1];
        }
        if pos2 < 14 {
            uuid_bytes[pos2] = target_byte2 ^ UUID_XOR[pos2];
        }

        // If both positions are in 14-byte range, we can force the CRC normally
        if pos1 < 14 && pos2 < 14 {
            let success = Self::forge_bruteforce(&mut uuid_bytes, target_crc, &[0, pos1, pos2]);
            if !success {
                panic!("Failed to forge CRC16");
            }

            let mut final_uuid_bytes = [0u8; 16];
            final_uuid_bytes[0..14].copy_from_slice(&uuid_bytes);
            final_uuid_bytes[14..16].copy_from_slice(&target_crc.to_le_bytes());

            let final_id = Uuid::from_slice(&final_uuid_bytes).unwrap();

            return Self {
                src_bytes: uuid_bytes,
                crc16: target_crc,
                final_id,
            };
        }

        // If we reach here, we failed to find a valid combination
        panic!("Failed to forge SceneID with target {target}");
    }


    /// Attempts to adjust two bytes in uuid_bytes to achieve the target CRC16,
    /// avoiding modifications to the bytes at exclude_positions.
    ///
    /// This is `O(2^16)` in the worst case.
    fn forge_bruteforce(
        uuid_bytes: &mut [u8; 14],
        target_crc: u16,
        exclude_positions: &[usize],
    ) -> bool {
        // Find two modifiable positions not in exclude_positions
        let mut modifiable = [0usize; 14];
        let mut mod_len = 0;
        for i in 0..14 {
            if !exclude_positions.contains(&i) {
                modifiable[mod_len] = i;
                mod_len += 1;
            }
        }

        if mod_len < 2 {
            return false;
        }
        let pos_a = modifiable[0];
        let pos_b = modifiable[1];

        let original_a = uuid_bytes[pos_a];
        let original_b = uuid_bytes[pos_b];

        for a in 0..=255u8 {
            for b in 0..=255u8 {
                uuid_bytes[pos_a] = a;
                uuid_bytes[pos_b] = b;

                let mut crc = crc16::State::<crc16::AUG_CCITT>::new();
                crc.update(uuid_bytes);

                if crc.get() == target_crc {
                    return true;
                }
            }
        }

        // Restore original bytes
        uuid_bytes[pos_a] = original_a;
        uuid_bytes[pos_b] = original_b;

        false
    }
}

impl Display for SceneID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.final_id)
    }
}

impl Display for SceneIDError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUUID => write!(f, "Invalid UUID"),
            Self::InvalidCRC16 => write!(f, "Invalid CRC16"),
        }
    }
}

