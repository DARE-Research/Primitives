use super::Bytes;
use alloy_rlp::{Decodable, Encodable};

impl Encodable for Bytes {
    #[inline]
    fn length(&self) -> usize {
        self.inner.length()
    }

    #[inline]
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        self.inner.encode(out);
    }
}

impl Decodable for Bytes {
    #[inline]
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        bytes::Bytes::decode(buf).map(|inner| Self { 
            inner: inner.to_vec().into_boxed_slice()
        })
    }
}

#[test]
fn test_rlp_decode_contents() {
    let original = Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let mut encoded = Vec::new();
    original.encode(&mut encoded);
    
    let mut slice = encoded.as_slice();
    let decoded = Bytes::decode(&mut slice).unwrap();
    
    assert_eq!(decoded.as_ref(), [0xDE, 0xAD, 0xBE, 0xEF]);
}