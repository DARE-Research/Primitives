use core::arch::aarch64::*;
use core::{fmt, ops, str};
use derive_more::{Deref, DerefMut, From, Index, IndexMut, IntoIterator};
use hex::Buffer;
use hex::FromHex;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deref,
    DerefMut,
    From,
    Index,
    IndexMut,
    IntoIterator,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(derive_arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
#[cfg_attr(feature = "allocative", derive(allocative::Allocative))]
#[repr(transparent)]
pub struct FixedBytes<const N: usize>(#[into_iterator(owned, ref, ref_mut)] pub [u8; N]);

impl<const N: usize> Default for FixedBytes<N> {
    #[inline(always)]
    fn default() -> Self {
        Self::ZERO
    }
}

impl<const N: usize> TryFrom<&[u8]> for FixedBytes<N> {
    type Error = core::array::TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; N]>::try_from(slice).map(Self)
    }
}

impl<'a, const N: usize> Default for &'a FixedBytes<N> {
    #[inline(always)]
    fn default() -> Self {
        &FixedBytes::ZERO
    }
}

impl<const N: usize> FromHex for FixedBytes<N> {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = hex::decode(hex)?; 
        if bytes.len() != N {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        Ok(Self(bytes.try_into().unwrap()))
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl<const N: usize> fmt::Display for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // If the alternate flag is NOT set, we write the full hex.
        if N <= 4 || !f.alternate() {
            return self.fmt_hex::<false>(f, true);
        }

        // If the alternate flag is set, we use middle-out compression.
        const SEP_LEN: usize = '…'.len_utf8();
        let mut buf = [0; 2 + 4 + SEP_LEN + 4];
        buf[0] = b'0';
        buf[1] = b'x';
        hex::encode_to_slice(&self.0[0..2], &mut buf[2..6]).unwrap();
        '…'.encode_utf8(&mut buf[6..]);
        hex::encode_to_slice(&self.0[N - 2..N], &mut buf[6 + SEP_LEN..]).unwrap();

        // SAFETY: always valid UTF-8
        f.write_str(unsafe { str::from_utf8_unchecked(&buf) })
    }
}

//uselsssssssssss
impl<const N: usize> fmt::LowerHex for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

//uselessssssss
impl<const N: usize> fmt::UpperHex for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl<const N: usize> ops::BitAnd for FixedBytes<N> {
    type Output = Self;

    #[inline]
    fn bitand(mut self, rhs: Self) -> Self::Output {
        self &= rhs;
        self
    }
}

impl<const N: usize> ops::BitAndAssign for FixedBytes<N> {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a &= *b;
        }
    }
}

impl<const N: usize> ops::BitOr for FixedBytes<N> {
    type Output = Self;

    #[inline]
    fn bitor(mut self, rhs: Self) -> Self::Output {
        self |= rhs;
        self
    }
}

impl<const N: usize> ops::BitOrAssign for FixedBytes<N> {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a |= *b;
        }
    }
}

impl<const N: usize> ops::BitXor for FixedBytes<N> {
    type Output = Self;

    #[inline]
    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl<const N: usize> ops::BitXorAssign for FixedBytes<N> {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= *b;
        }
    }
}

impl<const N: usize> ops::Not for FixedBytes<N> {
    type Output = Self;

    #[inline]
    fn not(mut self) -> Self::Output {
        for byte in &mut self.0 {
            *byte = !*byte;
        }
        self
    }
}

impl<const N: usize> str::FromStr for FixedBytes<N> {
    type Err = hex::FromHexError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl<const N: usize> FixedBytes<N> {
    pub const ZERO: Self = Self([0u8; N]);

    #[inline(always)]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    #[inline(always)]
    pub const fn with_last_byte(x: u8) -> Self {
        let mut bytes = [0u8; N];
        if N > 0 {
            bytes[N - 1] = x;
        }
        Self(bytes)
    }

    #[inline(always)]
    pub const fn repeat_byte(byte: u8) -> Self {
        Self([byte; N])
    }

    #[inline(always)]
    pub const fn len_bytes() -> usize {
        N
    }

    fn fmt_hex<const UPPER: bool>(&self, f: &mut fmt::Formatter<'_>, prefix: bool) -> fmt::Result {
        let mut buf = Buffer::<N, true>::new();
        let s = if UPPER {
            buf.format_upper(self)
        } else {
            buf.format(self)
        };
        // SAFETY: The buffer is guaranteed to be at least 2 bytes in length.
        f.write_str(unsafe { s.get_unchecked((!prefix as usize) * 2..) })
    }

    #[inline]
    pub fn from_slice(src: &[u8]) -> Self {
        Self::try_from(src).expect("slice length does not match")
    }

    #[inline]
    pub fn left_padding_from(value: &[u8]) -> Self {
        assert!(value.len() <= N, "slice is too large");
        let mut bytes = Self::ZERO;
        bytes.0[N - value.len()..].copy_from_slice(value);
        bytes
    }

    #[inline]
    pub fn right_padding_from(value: &[u8]) -> Self {
        assert!(value.len() <= N, "slice is too large");
        let mut bytes = Self::ZERO;
        bytes.0[..value.len()].copy_from_slice(value);
        bytes
    }

    #[inline(always)]
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    #[inline]
    pub fn covers(&self, other: &Self) -> bool {
        (*self & *other) == *other
    }

    pub const fn const_covers(self, other: Self) -> bool {
        self.bit_and(other).const_eq(&other)
    }

    pub const fn const_eq(&self, other: &Self) -> bool {
        let mut i = 0;
        while i < N {
            if self.0[i] != other.0[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub unsafe fn is_zero_simd(&self) -> bool {
        let chunks = N / 16;
        let zero = vdupq_n_u8(0);

        for i in 0..chunks {
            let a = vld1q_u8(self.0.as_ptr().add(i * 16));
            if vminvq_u8(vceqq_u8(a, zero)) == 0 {
                return false;
            }
        }
        self.0[chunks * 16..].iter().all(|&x| x == 0)
    }

    #[inline]
    pub const fn const_is_zero(&self) -> bool {
        self.const_eq(&Self::ZERO)
    }

    pub const fn bit_and(self, rhs: Self) -> Self {
        let mut ret = Self::ZERO;
        let mut i = 0;
        while i < N {
            ret.0[i] = self.0[i] & rhs.0[i];
            i += 1;
        }
        ret
    }

    #[target_feature(enable = "neon")]
    pub unsafe fn bit_and_simd(&self, other: &Self) -> Self {
        let mut result = Self::ZERO;
        for (i, (a, b)) in self.0.chunks(16).zip(other.0.chunks(16)).enumerate() {
            let va = vld1q_u8(a.as_ptr());
            let vb = vld1q_u8(b.as_ptr());
            let vr = vandq_u8(va, vb);
            vst1q_u8(result.0.as_mut_ptr().add(i * 16), vr);
        }
        result
    }

    pub const fn bit_or(self, rhs: Self) -> Self {
        let mut ret = Self::ZERO;
        let mut i = 0;
        while i < N {
            ret.0[i] = self.0[i] | rhs.0[i];
            i += 1;
        }
        ret
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub unsafe fn bit_or_simd(&self, other: &Self) -> Self {
        let mut result = Self::ZERO;
        for (i, (a, b)) in self.0.chunks(16).zip(other.0.chunks(16)).enumerate() {
            let va = vld1q_u8(a.as_ptr());
            let vb = vld1q_u8(b.as_ptr());
            let vr = vorrq_u8(va, vb);
            vst1q_u8(result.0.as_mut_ptr().add(i * 16), vr);
        }
        result
    }

    pub const fn bit_xor(self, rhs: Self) -> Self {
        let mut ret = Self::ZERO;
        let mut i = 0;
        while i < N {
            ret.0[i] = self.0[i] ^ rhs.0[i];
            i += 1;
        }
        ret
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub unsafe fn bit_xor_simd(&self, other: &Self) -> Self {
        let mut result = Self::ZERO;
        for (i, (a, b)) in self.0.chunks(16).zip(other.0.chunks(16)).enumerate() {
            let va = vld1q_u8(a.as_ptr());
            let vb = vld1q_u8(b.as_ptr());
            let vr = veorq_u8(va, vb);
            vst1q_u8(result.0.as_mut_ptr().add(i * 16), vr);
        }
        result
    }

    pub const fn concat_const<const M: usize, const Z: usize>(
        self,
        other: FixedBytes<M>,
    ) -> FixedBytes<Z> {
        assert!(
            N + M == Z,
            "Output size `Z` must equal the sum of the input sizes `N` and `M`"
        );

        let mut result = [0u8; Z];
        let mut i = 0;
        while i < N {
            result[i] = self.0[i];
            i += 1;
        }
        let mut j = 0;
        while j < M {
            result[i + j] = other.0[j];
            j += 1;
        }
        FixedBytes(result)
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub unsafe fn eq_simd(&self, other: &Self) -> bool {
        for (a, b) in self.0.chunks(16).zip(other.0.chunks(16)) {
            let va = vld1q_u8(a.as_ptr());
            let vb = vld1q_u8(b.as_ptr());
            if vminvq_u8(vceqq_u8(va, vb)) == 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    macro_rules! fixed_bytes {
        ($hex:literal, $N:expr) => {
            FixedBytes::<$N>::from_slice(&hex::decode($hex).unwrap())
        };
    }

    macro_rules! test_fmt {
        ($($fmt:literal, $hex:literal, $N:expr => $expected:literal;)+) => {$(
            assert_eq!(
                format!($fmt, fixed_bytes!($hex, $N)),
                $expected
            );
        )+};
    }

    #[test]
    fn concat_const() {
        let time = Instant::now();
        const A: FixedBytes<2> = FixedBytes([0x01, 0x23]);
        const B: FixedBytes<2> = FixedBytes([0x45, 0x67]);
        const EXPECTED: FixedBytes<4> = FixedBytes([0x01, 0x23, 0x45, 0x67]);
        const ACTUAL: FixedBytes<4> = A.concat_const(B);

        assert_eq!(ACTUAL, EXPECTED);
        println!("{:?}", time.elapsed());
    }

    #[test]
    #[should_panic(expected = "slice is too large")]
    fn left_padding_from_too_large() {
        let time = Instant::now();
        FixedBytes::<4>::left_padding_from(&[0x01, 0x23, 0x45, 0x67, 0x89]);
        println!("{:?}", time.elapsed());
    }

    #[test]
    #[should_panic(expected = "slice length does not match")]
    fn test_from_slice_panic() {
        let slice = [0x01, 0x23, 0x45];
        FixedBytes::<4>::from_slice(&slice);
    }

    #[test]
    fn test_is_zero() {}
}
