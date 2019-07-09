use crate::error::DbusParseError;
use crate::header::components::MessageEndianness;
use crate::signature_type::{Signature, SignatureType};
use crate::types::basic::DbusUint32;
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
    const ALIGNMENT: usize = 1;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        _: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let (buf, len) = match endianness {
            MessageEndianness::BigEndian => map(be_u32, |v| v as usize)(buf),
            MessageEndianness::LittleEndian => map(le_u32, |v| v as usize)(buf),
        }?;

        let (buf, s) = map(map_res(take(len), std::str::from_utf8), |v| Self(v.into()))(buf)?;

        if s.0.len() != len {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        let (buf, nul) = take(1usize)(buf)?;
        if nul.len() != 1 || nul[0] != b'\0' {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        Ok((buf, s))
    }

    fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
        let string_len = self.0.len();
        let alloc_len = string_len + 5;
        let mut res = Vec::with_capacity(alloc_len);
        res.append(&mut DbusUint32::marshal(
            (string_len as u32).into(),
            endianness,
        )?);
        res.append(&mut self.0.into_bytes());
        res.push(b'\0');
        Ok(res)
    }
}

impl From<Signature> for DbusSignature {
    fn from(value: Signature) -> Self {
        Self(
            value
                .into_inner()
                .into_iter()
                .fold(String::new(), |mut s, signature_type| {
                    s.push(signature_type as u8 as char);
                    s
                }),
        )
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
