use crate::error::DbusParseError;
use crate::header::components::MessageEndianness;
use crate::signature_type::Signature;
use crate::types::basic::integer::DbusUint32;
use crate::DbusType;
use nom::combinator::map;
use nom::number::streaming::{be_u32, le_u32};
use nom::IResult;

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
