use nom::combinator::map;
use nom::number::streaming::{be_u32, le_u32};
use crate::header::components::MessageEndianness;
use crate::DbusType;
use nom::IResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbusBoolean(bool);

impl DbusType for DbusBoolean {
    fn parse(buf: &[u8], endianness: Option<MessageEndianness>) -> IResult<&[u8], Self> {
        map(
            endianness.map(|e| match e {
                MessageEndianness::BigEndian => be_u32,
                MessageEndianness::LittleEndian => le_u32,
            }).unwrap_or_else(|| le_u32),
            |v: u32| DbusBoolean(v != 0u32),
        )(buf)
    }
}
