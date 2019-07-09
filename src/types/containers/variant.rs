use crate::error::DbusParseError;
use crate::header::components::MessageEndianness;
use crate::types::basic::*;
use crate::{DbusType, DbusTypeContainer};
use crate::{Signature, SignatureType};
use nom::IResult;
use std::convert::{TryFrom, TryInto};

macro_rules! impl_try_from {
    ($target:ty, $source:ty, $sig:expr) => {
        impl TryFrom<$source> for $target {
            type Error = DbusParseError;

            fn try_from(value: $source) -> Result<Self, Self::Error> {
                Ok(Self {
                    signature: Signature::from($sig).into(),
                    inner: value.try_into()?,
                })
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq)]
pub struct DbusVariant {
    signature: DbusSignature,
    inner: DbusTypeContainer,
}

impl_try_from!(DbusVariant, DbusString, SignatureType::String);
impl_try_from!(DbusVariant, DbusSignature, SignatureType::Signature);
impl_try_from!(DbusVariant, DbusObjectPath, SignatureType::ObjectPath);
impl_try_from!(DbusVariant, DbusBoolean, SignatureType::Boolean);
impl_try_from!(DbusVariant, DbusByte, SignatureType::Byte);
impl_try_from!(DbusVariant, DbusUint16, SignatureType::Uint16);
impl_try_from!(DbusVariant, DbusInt16, SignatureType::Int16);
impl_try_from!(DbusVariant, DbusUint32, SignatureType::Uint32);
impl_try_from!(DbusVariant, DbusInt32, SignatureType::Int32);
impl_try_from!(DbusVariant, DbusUint64, SignatureType::Uint64);
impl_try_from!(DbusVariant, DbusInt64, SignatureType::Int64);
impl_try_from!(DbusVariant, DbusDouble, SignatureType::Double);
impl_try_from!(DbusVariant, DbusUnixFd, SignatureType::UnixFd);

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
        let mut buf = self.signature.marshal(endianness)?;
        buf.extend(self.inner.marshal(endianness)?);
        Ok(buf)
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
