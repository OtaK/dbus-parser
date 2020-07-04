use crate::{
    error::DbusParseError, header::components::MessageEndianness, signature_type::Signature,
    types::basic::integer::DbusUint32, DbusType,
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
