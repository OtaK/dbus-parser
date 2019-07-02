use crate::header::components::MessageEndianness;
use crate::signature_type::Signature;
use crate::type_container::DbusTypeContainer;
use crate::{DbusParseError, DbusType};
use nom::combinator::iterator;
use nom::IResult;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

#[derive(Debug, Clone, PartialEq)]
pub struct DbusStruct(Vec<DbusTypeContainer>);

impl DbusType for DbusStruct {
    const ALIGNMENT: usize = 8;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        signature: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let (buf, inner) = signature.parse_buffer(buf, endianness, signature)?;
        Ok((buf, Self(inner)))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DbusDictEntry(DbusTypeContainer, DbusTypeContainer);

impl DbusType for DbusDictEntry {
    const ALIGNMENT: usize = 8;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        signature: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let (buf, inner) = signature.parse_buffer(buf, endianness, &signature)?;
        if inner.len() != 2 {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        let mut iter = inner.into_iter();
        let v1 = iter.next().unwrap().into();
        let v2 = iter.next().unwrap().into();

        Ok((buf, Self(v1, v2)))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DbusDict(Vec<DbusDictEntry>);

impl DbusDict {
    pub fn new(inner: Vec<DbusDictEntry>) -> Self {
        Self(inner)
    }
}

impl From<Vec<DbusTypeContainer>> for DbusDict {
    fn from(v: Vec<DbusTypeContainer>) -> Self {
        Self(
            v.chunks(2)
                .map(|tmp| DbusDictEntry(tmp[0].clone(), tmp[1].clone()))
                .collect(),
        )
    }
}

impl DbusType for DbusDict {
    const ALIGNMENT: usize = 8;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        signature: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let mut it = iterator(buf, |buf| {
            DbusDictEntry::unmarshal(buf, endianness, signature)
        });

        let inner = it.collect();
        let (buf, _) = it.finish()?;

        Ok((buf, Self(inner)))
    }
}

impl<
        K: TryFrom<DbusTypeContainer, Error = DbusParseError> + Eq + std::hash::Hash,
        V: TryFrom<DbusTypeContainer, Error = DbusParseError>,
    > TryInto<HashMap<K, V>> for DbusDict
{
    type Error = DbusParseError;

    fn try_into(self) -> Result<HashMap<K, V>, Self::Error> {
        self.0
            .into_iter()
            .try_fold(HashMap::default(), |mut hash, current_entry| {
                let k = current_entry.0.try_into()?;
                let v = current_entry.1.try_into()?;
                hash.insert(k, v);

                Ok(hash)
            })
    }
}
