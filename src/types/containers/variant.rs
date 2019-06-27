use crate::header::components::MessageEndianness;
use crate::types::basic::*;
use crate::{DbusTypeContainer, DbusType};
use crate::Signature;
use nom::IResult;
use std::convert::TryInto;

#[derive(Debug, Clone, PartialEq)]
pub struct DbusVariant {
    signature: DbusSignature,
    inner: DbusTypeContainer,
}

impl DbusType for DbusVariant {
    fn parse(buf: &[u8], endianness: Option<MessageEndianness>) -> IResult<&[u8], Self> {
        let (buf, signature) = DbusSignature::parse(buf, endianness)?;
        let type_signature: Signature = signature.clone().try_into().map_err(|_| nom::Err::Failure((buf, nom::error::ErrorKind::Verify)))?;
        let (buf, inner) = type_signature.parse_buffer(buf, endianness).map(|(buf, inner)| (buf, inner.into_iter().next().unwrap()))?;

        Ok((buf, DbusVariant {
            inner,
            signature
        }))
    }
}
