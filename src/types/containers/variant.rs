use crate::header::components::MessageEndianness;
use crate::types::basic::*;
use crate::Signature;
use crate::{DbusType, DbusTypeContainer};
use nom::IResult;
use std::convert::TryInto;

#[derive(Debug, Clone, PartialEq)]
pub struct DbusVariant {
    signature: DbusSignature,
    inner: DbusTypeContainer,
}

impl DbusType for DbusVariant {
    const ALIGNMENT: usize = 1;

    fn parse<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        s: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let (buf, signature) = DbusSignature::parse(buf, endianness, s)?;

        let type_signature: Signature = signature
            .clone()
            .try_into()
            .map_err(|_| nom::Err::Failure((buf, nom::error::ErrorKind::Verify)))?;

        let (buf, inner) = type_signature
            .parse_buffer(buf, endianness, &type_signature)
            .map(|(buf, inner)| (buf, inner.into_iter().next().unwrap()))?;

        Ok((buf, DbusVariant { inner, signature }))
    }
}
