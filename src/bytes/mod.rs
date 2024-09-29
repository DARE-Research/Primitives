use core::{
     fmt,
    ops::{Deref, DerefMut},
     str::FromStr
};
use std:: boxed::Box;
use rand::Rng;
pub mod rlp;
pub mod serde;


#[cfg(target_arch = "aarch64")]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes {
    inner: Box<[u8]>,
}

impl Bytes {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Box::new([]),
        }
    }

    #[inline]
    pub fn from_static(bytes: &'static [u8]) -> Self {
        Self {
            inner: bytes.into(),
        }
    }

    #[inline]
    pub fn copy_from_slice(data: &[u8]) -> Self {
        Self { inner: data.into() }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    // SIMD-optimized hex encoding
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn to_hex(&self, uppercase: bool) -> String {
        let mut result = String::with_capacity(2 + self.len() * 2);
 
            result.push_str("0x");


        #[cfg(target_arch = "x86_64")]
        unsafe {
            self.to_hex_x86_64(&mut result, uppercase);
            return result;
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            self.to_hex_aarch64(&mut result, uppercase);
            return result;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn to_hex_x86_64(&self, result: &mut String, uppercase: bool) {
        use core::arch::x86_64::*;

        let lut_lower = _mm256_setr_epi8(
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
        );
        let lut_upper = _mm256_setr_epi8(
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F',
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F',
        );
        let lut = if uppercase { lut_upper } else { lut_lower };

        for chunk in self.inner.chunks(16) {
            let input = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            let hi = _mm256_and_si256(_mm256_srli_epi32(input, 4), _mm256_set1_epi8(0x0f));
            let lo = _mm256_and_si256(input, _mm256_set1_epi8(0x0f));

            let hi_hex = _mm256_shuffle_epi8(lut, hi);
            let lo_hex = _mm256_shuffle_epi8(lut, lo);

            let hex = _mm256_unpacklo_epi8(hi_hex, lo_hex);
            let hex_chars = core::slice::from_raw_parts(hex.as_ptr() as *const u8, 32);

            result.push_str(core::str::from_utf8_unchecked(&hex_chars[..chunk.len() * 2]));
        }
    }


    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub unsafe fn to_hex_aarch64(&self, result: &mut String, uppercase: bool) {
        use core::arch::aarch64::*;

        let additional_capacity = self.inner.len() * 2;
        result.reserve(additional_capacity);
  
        let lut_lower = vld1q_u8(b"0123456789abcdef".as_ptr());
        let lut_upper = vld1q_u8(b"0123456789ABCDEF".as_ptr());
        let lut = if uppercase { lut_upper } else { lut_lower };
        let mask_low = vdupq_n_u8(0x0f);
    
        let chunks = self.inner.chunks_exact(16);
        let remainder = chunks.remainder();
    
        for chunk in chunks {
            let input = vld1q_u8(chunk.as_ptr());
            
            let hi = vshrq_n_u8(input, 4);
            let lo = vandq_u8(input, mask_low);
            
            let hi_hex = vqtbl1q_u8(lut, hi);
            let lo_hex = vqtbl1q_u8(lut, lo);
            
            let res1 = vzip1q_u8(hi_hex, lo_hex);
            let res2 = vzip2q_u8(hi_hex, lo_hex);
    
            let bytes = result.as_mut_vec();
            let start = bytes.len();
            bytes.set_len(start + 32);
            
            vst1q_u8(bytes.as_mut_ptr().add(start), res1);
            vst1q_u8(bytes.as_mut_ptr().add(start + 16), res2);
        }

        if !remainder.is_empty() {
            let mut padded = [0u8; 16];
            padded[..remainder.len()].copy_from_slice(remainder);
            let input = vld1q_u8(padded.as_ptr());
            
            let hi = vshrq_n_u8(input, 4);
            let lo = vandq_u8(input, mask_low);
            
            let hi_hex = vqtbl1q_u8(lut, hi);
            let lo_hex = vqtbl1q_u8(lut, lo);
            
            let res1 = vzip1q_u8(hi_hex, lo_hex);
            let res2 = vzip2q_u8(hi_hex, lo_hex);
    
            let mut temp_buffer = [0u8; 32];
            vst1q_u8(temp_buffer.as_mut_ptr(), res1);
            vst1q_u8(temp_buffer.as_mut_ptr().add(16), res2);
            
            let valid_bytes = remainder.len() * 2;
            result.push_str(core::str::from_utf8_unchecked(&temp_buffer[..valid_bytes]));
        }
    }

    pub fn random() -> Self{
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 20];
        rng.fill(&mut bytes);
        Bytes{ inner: bytes.to_vec().into_boxed_slice()}
    }

}

impl Deref for Bytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Bytes {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self {
            inner: value.into_boxed_slice(),
        }
    }
}

impl From<Bytes> for Vec<u8> {
    #[inline]
    fn from(value: Bytes) -> Self {
        value.inner.into_vec()
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl FromStr for Bytes {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let vec = hex::decode(s)?;
        Ok(Bytes::from(vec))
    }
}

impl fmt::LowerHex for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.to_hex(false))
    }
}

impl fmt::UpperHex for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.to_hex(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test] 
    fn format() {
        let start = Instant::now();
        let b = Bytes::from_static(&[1, 35, 69, 103, 137, 171, 205, 239]);
        assert_eq!(format!("{b}"), "0x0123456789abcdef");
        assert_eq!(format!("{b:x}"), "0x0123456789abcdef");
        assert_eq!(format!("{b:?}"), "0x0123456789abcdef");
        assert_eq!(format!("{b:#?}"), "0x0123456789abcdef");
        assert_eq!(format!("{b:#x}"), "0x0123456789abcdef");
        assert_eq!(format!("{b:X}"), "0x0123456789ABCDEF");
        assert_eq!(format!("{b:#X}"), "0x0123456789ABCDEF");
        let stop = start.elapsed();
        println!("{:?}", stop);
    }

    #[test]
    fn parse() {
        let start = Instant::now();
        let expected = Bytes::from_static(&[0x12, 0x13, 0xab, 0xcd]);
        println!("{:?}", expected);
        assert_eq!("1213abcd".parse::<Bytes>().unwrap(), expected);
        assert_eq!("0x1213abcd".parse::<Bytes>().unwrap(), expected);
        assert_eq!("1213ABCD".parse::<Bytes>().unwrap(), expected);
        assert_eq!("0x1213ABCD".parse::<Bytes>().unwrap(), expected);
        let stop = start.elapsed();
        println!("{:?}", stop);
    }


    #[test]
    fn test_to_hex() {
        use std::time::Instant;
        let start = Instant::now();
        let bytes = Bytes::copy_from_slice(&[0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(bytes.to_hex(false), "0x1234abcd");
        let stop = start.elapsed();
        println!("{:?}", stop);
    }
}
