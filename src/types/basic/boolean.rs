use crate::{
    error::DbusParseError, header::components::MessageEndianness, signature_type::Signature,
    types::basic::number::DbusUint32, DbusType,
};

use nom::{
    combinator::map,
    number::streaming::{be_u32, le_u32},
    IResult,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbusBoolean(bool);

impl DbusType for DbusBoolean {
    const ALIGNMENT: usize = 4;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        _: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        map(
            match endianness {
                MessageEndianness::BigEndian => be_u32,
                MessageEndianness::LittleEndian => le_u32,
            },
            |v: u32| DbusBoolean(v != 0u32),
        )(buf)
    }

    fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
        DbusUint32::marshal((self.0 as u32).into(), endianness)
    }
}

impl From<bool> for DbusBoolean {
    fn from(v: bool) -> Self {
        Self(v)
    }
}

impl std::ops::Deref for DbusBoolean {
    type Target = bool;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LE_BOOL: [u8; 4] = [1, 0, 0, 0];
    const BE_BOOL: [u8; 4] = [0, 0, 0, 1];
    #[test]
    fn marshal_bool() {
        let b = DbusBoolean::from(true);
        let b_bytes_le = b.marshal(MessageEndianness::LittleEndian).unwrap();
        assert_eq!(LE_BOOL, *b_bytes_le);

        let b_bytes_be = b.marshal(MessageEndianness::BigEndian).unwrap();
        assert_eq!(BE_BOOL, *b_bytes_be);
    }

    #[test]
    fn unmarshal_bool() {
        let (_, b) = DbusBoolean::unmarshal(&LE_BOOL, MessageEndianness::LittleEndian, &crate::signature_type::SignatureType::Boolean.into()).unwrap();
        assert_eq!(*b, true);

        let (_, b) = DbusBoolean::unmarshal(&BE_BOOL, MessageEndianness::BigEndian, &crate::signature_type::SignatureType::Boolean.into()).unwrap();
        assert_eq!(*b, true);
    }
}
