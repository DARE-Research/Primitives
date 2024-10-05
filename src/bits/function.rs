use super::{address::Address, fixed::FixedBytes};
use core::borrow::Borrow;

pub struct Function([u8; 24]);

impl<A, S> From<(A, S)> for Function
where
    A: Borrow<[u8; 20]>,
    S: Borrow<[u8; 4]>,
{
    #[inline]
    fn from((address, selector): (A, S)) -> Self {
        Self::from_address_and_selector(address, selector)
    }
}


/// Solidity contract functions are addressed using the first four bytes of the
/// Keccak-256 hash of their signature.
pub type Selector = FixedBytes<4>;

impl Function {

    #[inline]
    pub const fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Creates an Ethereum function from an EVM word's lower 24 bytes
    /// (`word[..24]`).
    ///
    /// Note that this is different from `Address::from_word`, which uses the
    /// upper 20 bytes.
    #[inline]
    #[must_use]
    pub fn from_word(word: FixedBytes<32>) -> Self {
        // SAFETY: We know that word.0[..24] is always 24 bytes long
        unsafe { Self(*(word.0.as_ptr() as *const [u8; 24])) }
    }

    /// Right-pads the function to 32 bytes (EVM word size).
    ///
    /// Note that this is different from `Address::into_word`, which left-pads
    /// the address.
    #[inline]
    #[must_use]
    pub fn into_word(&self) -> FixedBytes<32> {
        let mut word = [0; 32];
        word[..24].copy_from_slice(&self.0);
        FixedBytes(word)
    }

    #[inline]
    pub fn from_address_and_selector<A, S>(address: A, selector: S) -> Self
    where
        A: Borrow<[u8; 20]>,
        S: Borrow<[u8; 4]>,
    {
        let mut bytes = [0; 24];
        bytes[..20].copy_from_slice(address.borrow());
        bytes[20..].copy_from_slice(selector.borrow());
        Self(bytes)
    }

    #[inline]
    pub fn as_address_and_selector(&self) -> (&Address, &Selector) {
               // SAFETY: Function (24) = Address (20) + Selector (4)
               unsafe {
                (
                    &*(self.0.as_ptr() as *const Address),
                    &*(self.0.as_ptr().add(20) as *const Selector),
                )
            }
    
    }

 
    #[inline]
    pub fn to_address_and_selector(&self) -> (Address, Selector) {
        let (a, s) = self.as_address_and_selector();
        (*a, *s)
    }
}

