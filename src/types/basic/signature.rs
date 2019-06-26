
use crate::header::components::MessageEndianness;
use crate::DbusParseError;
use crate::DbusType;
use core::convert::TryFrom;
use nom::bytes::streaming::*;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::number::streaming::{be_u32, le_u32};
use nom::IResult;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DbusSignature(String);

impl TryFrom<String> for DbusSignature {
    type Error = DbusParseError;

    fn try_from(_v: String) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl DbusType for DbusSignature {
    fn parse(buf: &[u8], e: Option<MessageEndianness>) -> IResult<&[u8], Self> {
        let (buf, len) =
            match e.ok_or_else(|| nom::Err::Failure((buf, nom::error::ErrorKind::Verify)))? {
                MessageEndianness::BigEndian => be_u32(buf),
                MessageEndianness::LittleEndian => le_u32(buf),
            }?;

        let (buf, s) = map_res(
            map(map_res(take(len), std::str::from_utf8), String::from),
            Self::try_from,
        )(buf)?;

        if s.0.len() != len as usize {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        let (buf, nul) = take(1usize)(buf)?;
        if nul.len() != 1 || nul[0] != b'\0' {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        Ok((buf, s))
    }
}
