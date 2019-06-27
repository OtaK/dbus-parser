
use crate::error::DbusParseError;
use crate::header::components::MessageEndianness;
use crate::signature_type::{Signature, SignatureType};
use crate::DbusType;

use nom::bytes::streaming::*;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::number::streaming::{be_u32, le_u32};
use nom::IResult;
use std::convert::{TryFrom, TryInto};
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DbusSignature(String);

impl DbusType for DbusSignature {
    fn parse(buf: &[u8], e: Option<MessageEndianness>) -> IResult<&[u8], Self> {
        let (buf, len) =
            match e.ok_or_else(|| nom::Err::Failure((buf, nom::error::ErrorKind::Verify)))? {
                MessageEndianness::BigEndian => be_u32(buf),
                MessageEndianness::LittleEndian => le_u32(buf),
            }?;

        let (buf, s) = map(map_res(take(len), std::str::from_utf8), |v| Self(v.into()))(buf)?;

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

impl TryInto<Signature> for DbusSignature {
    type Error = DbusParseError;

    fn try_into(self) -> Result<Signature, Self::Error> {
        self.0
            .chars()
            .into_iter()
            .try_fold(Signature::default(), |mut sig, character| {
                (*sig).push(SignatureType::try_from(character as u8)?);
                Ok(sig)
            })
    }
}
