use core::arch::aarch64::*;
use core::{fmt, mem::MaybeUninit, str, str::FromStr};
use hex::{self, FromHex};
use keccak_asm::{Digest, Keccak256};
use rand::Rng;


#[derive(Clone)]
pub struct AddressChecksumBuffer(MaybeUninit<[u8; 42]>);
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

impl AddressChecksumBuffer {
    /// Creates a new uninitialized buffer.
    ///
    /// # Safety
    ///
    /// The buffer must be initialized with `format` before use.
    #[inline]
    pub const unsafe fn new() -> Self {
        Self(MaybeUninit::uninit())
    }

    /// Returns the checksum as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(self.0.assume_init_ref()) }
    }

    /// Returns the checksum as a mutable string slice.
    #[inline]
    pub fn as_mut_str(&mut self) -> &mut str {
        unsafe { str::from_utf8_unchecked_mut(self.0.assume_init_mut()) }
    }

    /// Converts the buffer to a String.
    #[inline]
    pub fn to_string(&self) -> String {
        self.as_str().to_string()
    }

    /// Returns the underlying byte array.
    #[inline]
    pub fn into_inner(self) -> [u8; 42] {
        unsafe { self.0.assume_init() }
    }
}

impl fmt::Debug for AddressChecksumBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AddressChecksumBuffer")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for AddressChecksumBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum AddressError {
    Hex(hex::FromHexError),
    InvalidLength,
    InvalidChecksum,
}

#[repr(align(8))]
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Address([u8; 20]);

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() != 40 {
            return Err(AddressError::InvalidLength);
        }

        let bytes = Vec::from_hex(s).map_err(AddressError::Hex)?;
        if bytes.len() != 20 {
            return Err(AddressError::InvalidLength);
        }

        Ok(Address(bytes.try_into().unwrap()))
    }
}

impl From<hex::FromHexError> for AddressError {
    fn from(err: hex::FromHexError) -> Self {
        AddressError::Hex(err)
    }
}

impl Address {
    pub fn parse_checksummed(s: &str, chain_id: Option<u64>) -> Result<Self, AddressError> {
        let address = Self::from_str(s)?;

        let calculated_checksum = address.to_checksum(chain_id);
    
        if s.eq_ignore_ascii_case(&calculated_checksum) {
            Ok(address)
        } else {
            Err(AddressError::InvalidChecksum)
        }
    }

    pub fn to_checksum(&self, chain_id: Option<u64>) -> String {
        self.to_checksum_buffer(chain_id).to_string()
    }

    #[inline(always)]
    pub fn to_checksum_buffer(&self, chain_id: Option<u64>) -> AddressChecksumBuffer {
        let mut buf = unsafe { AddressChecksumBuffer::new() };
        #[cfg(target_arch = "aarch64")]
        {
            use std::arch::is_aarch64_feature_detected;
            if is_aarch64_feature_detected!("neon") {
                unsafe {
                  self.to_checksum_inner_simd( buf.0.assume_init_mut(), chain_id);
                }
                return buf;
            }
        }
        self.to_checksum_inner(unsafe{ buf.0.assume_init_mut() }, chain_id);
        buf
    }

    #[inline(always)]
    pub fn to_checksum_inner(&self, buf: &mut [u8; 42], chain_id: Option<u64>) {
        buf[0] = b'0';
        buf[1] = b'x';

        for (i, byte) in self.0.iter().enumerate() {
            buf[2 + i * 2] = HEX_CHARS[(byte >> 4) as usize];
            buf[2 + i * 2 + 1] = HEX_CHARS[(byte & 0xf) as usize];
        }

        let mut hasher = Keccak256::new();
        if let Some(id) = chain_id {
            // EIP-1191: Include chain ID in the hash calculation
            //overhead(id.to_string().bytes())
            for ch in id.to_string().bytes() {
                hasher.update(&[ch]);
            }
            hasher.update(b"0x");
        }
        hasher.update(&buf[2..]);
        let hash = hasher.finalize();

        for (i, ch) in buf[2..].iter_mut().enumerate() {
            let hash_byte = hash[i / 2];
            let hash_bit = (hash_byte >> (4 * (1 - i % 2))) & 0xf;
            if *ch > b'9' && hash_bit >= 8 {
                *ch = ch.to_ascii_uppercase();
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub unsafe fn to_checksum_inner_simd(&self, buf: &mut [u8; 42], chain_id: Option<u64>) {
        debug_assert_eq!(self.0.len(), 20, "Input must be exactly 20 bytes");
        buf[0] = b'0';
        buf[1] = b'x';

        // Convert bytes to lowercase hex characters
        for (i, &byte) in self.0.iter().enumerate() {
            buf[2 + i * 2] = HEX_CHARS[(byte >> 4) as usize];
            buf[2 + i * 2 + 1] = HEX_CHARS[(byte & 0xf) as usize];
        }

        // Keccak256 hash calculation
        let mut hasher = Keccak256::new();
        if let Some(id) = chain_id {
            for ch in id.to_string().bytes() {
                hasher.update(&[ch]);
            }
            hasher.update(b"0x");
        }
        hasher.update(&buf[2..]);
        let hash = hasher.finalize();

        // Apply checksum using SIMD
        let nine_ascii = vdupq_n_u8(b'9');
        let case_mask = vdupq_n_u8(0x20);
        for i in (0..40).step_by(16) {
            let chars = vld1q_u8(buf[2 + i..].as_ptr());
            let hash_bytes = vld1q_u8(hash[i / 2..].as_ptr());
            let hash_bits = vorrq_u8(
                vshlq_n_u8(vandq_u8(hash_bytes, vdupq_n_u8(0xf0)), 1),
                vshrq_n_u8(vandq_u8(hash_bytes, vdupq_n_u8(0x0f)), 3),
            );
            let is_alpha = vcgtq_u8(chars, nine_ascii);
            let should_be_uppercase = vcgeq_u8(hash_bits, vdupq_n_u8(8));
            let change_case = vandq_u8(is_alpha, should_be_uppercase);
            let result = veorq_u8(chars, vandq_u8(change_case, case_mask));
            vst1q_u8(buf[2 + i..].as_mut_ptr(), result);
        }

        for i in 0..40 {
            let char = buf[i + 2];
            if char > b'9' {
                let hash_byte = hash[i / 2];
                let hash_bit = (hash_byte >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
                if hash_bit >= 8 {
                    buf[i + 2] = char.to_ascii_uppercase();
                } else {
                    buf[i + 2] = char.to_ascii_lowercase();
                }
            }
        }
    }

    pub fn random() -> Self{
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 20];
        rng.fill(&mut bytes);
        Address(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::time::Instant;

    #[test]
    fn parse() {
        let expected = hex!("0102030405060708090a0b0c0d0e0f1011121314");
        assert_eq!(
            ("0102030405060708090a0b0c0d0e0f1011121314"
                .parse::<Address>()
                .unwrap()
                .0),
            expected
        );
    }

    // https://eips.ethereum.org/EIPS/eip-55
    #[test]
    fn checksum() {
        let start = Instant::now();
        let addresses = [
            // All caps
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            // All Lower
            "0xde709f2102306220921060314715629080e2fb77",
            "0x27b1fdb04752bbc536007a920d24acb045561c26",
            // Normal
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];
        for addr in addresses {
            let parsed1: Address = addr.parse().unwrap();
            let parsed2 = Address::parse_checksummed(addr, None).unwrap();
            assert_eq!(parsed1, parsed2);
            assert_eq!(parsed2.to_checksum(None), addr);
        }
        let stop = start.elapsed();
        println!("{:?}", stop);
    }

    // https://eips.ethereum.org/EIPS/eip-1191
    #[test]
    fn checksum_chain_id() {
        let start = Instant::now();
        let eth_mainnet = [
            "0x27b1fdb04752bbc536007a920d24acb045561c26",
            "0x3599689E6292b81B2d85451025146515070129Bb",
            "0x42712D45473476b98452f434e72461577D686318",
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x6549f4939460DE12611948b3f82b88C3C8975323",
            "0x66f9664f97F2b50F62D13eA064982f936dE76657",
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            "0x88021160C5C792225E4E5452585947470010289D",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xde709f2102306220921060314715629080e2fb77",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        ];
        let rsk_mainnet = [
            "0x27b1FdB04752BBc536007A920D24ACB045561c26",
            "0x3599689E6292B81B2D85451025146515070129Bb",
            "0x42712D45473476B98452f434E72461577d686318",
            "0x52908400098527886E0F7030069857D2E4169ee7",
            "0x5aaEB6053f3e94c9b9a09f33669435E7ef1bEAeD",
            "0x6549F4939460DE12611948B3F82B88C3C8975323",
            "0x66F9664f97f2B50F62d13EA064982F936de76657",
            "0x8617E340b3D01Fa5f11f306f4090fd50E238070D",
            "0x88021160c5C792225E4E5452585947470010289d",
            "0xD1220A0Cf47c7B9BE7a2e6ba89F429762E7B9adB",
            "0xDBF03B407c01E7CD3cBea99509D93F8Dddc8C6FB",
            "0xDe709F2102306220921060314715629080e2FB77",
            "0xFb6916095cA1Df60bb79ce92cE3EA74c37c5d359",
        ];
        let rsk_testnet = [
            "0x27B1FdB04752BbC536007a920D24acB045561C26",
            "0x3599689e6292b81b2D85451025146515070129Bb",
            "0x42712D45473476B98452F434E72461577D686318",
            "0x52908400098527886E0F7030069857D2e4169EE7",
            "0x5aAeb6053F3e94c9b9A09F33669435E7EF1BEaEd",
            "0x6549f4939460dE12611948b3f82b88C3c8975323",
            "0x66f9664F97F2b50f62d13eA064982F936DE76657",
            "0x8617e340b3D01fa5F11f306F4090Fd50e238070d",
            "0x88021160c5C792225E4E5452585947470010289d",
            "0xd1220a0CF47c7B9Be7A2E6Ba89f429762E7b9adB",
            "0xdbF03B407C01E7cd3cbEa99509D93f8dDDc8C6fB",
            "0xDE709F2102306220921060314715629080e2Fb77",
            "0xFb6916095CA1dF60bb79CE92ce3Ea74C37c5D359",
        ];
        for (addresses, chain_id) in [(eth_mainnet, 1), (rsk_mainnet, 30), (rsk_testnet, 31)] {
            // EIP-1191 test cases treat mainnet as "not adopted"
            let id = if chain_id == 1 { None } else { Some(chain_id) };
            for addr in addresses {
                let parsed1: Address = addr.parse().unwrap();
                println!("{:?}", addr);
                let parsed2 = Address::parse_checksummed(addr, id).unwrap();

                assert_eq!(parsed1, parsed2);
                assert_eq!(parsed2.to_checksum(id), addr);
            }
        }
        let stop = start.elapsed();
        println!("{:?}", stop);
    }
}
