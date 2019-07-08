use crate::error::DbusParseError;
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

impl DbusVariant {
    pub fn into_inner(self) -> DbusTypeContainer {
        self.inner
    }
}

impl DbusType for DbusVariant {
    const ALIGNMENT: usize = 1;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        s: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let (buf, signature) = DbusSignature::unmarshal(buf, endianness, s)?;

        let type_signature: Signature = signature
            .clone()
            .try_into()
            .map_err(|_| nom::Err::Failure((buf, nom::error::ErrorKind::Verify)))?;

        let (buf, inner) = type_signature
            .parse_buffer(buf, endianness)
            .map(|(buf, inner)| (buf, inner.into_iter().next().unwrap()))?;

        Ok((buf, DbusVariant { inner, signature }))
    }

    fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
        unimplemented!()
    }
}

impl std::ops::Deref for DbusVariant {
    type Target = DbusTypeContainer;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for DbusVariant {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
