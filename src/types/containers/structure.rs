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
        let (buf, inner) = signature.parse_buffer(buf, endianness)?;
        Ok((buf, Self(inner)))
    }

    fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
        let items_count = self.0.len();
        let mut inner_marshalled = self.0.into_iter().try_fold(
            Vec::with_capacity(items_count * Self::ALIGNMENT),
            |mut buf, current_entry| {
                buf.extend(current_entry.marshal(endianness)?);
                let pad = buf.len() % Self::ALIGNMENT;
                if pad > 0 {
                    buf.extend(vec![0; pad]);
                }

                Ok(buf)
            },
        )?;

        let inner_len = inner_marshalled.len();

        if inner_len > DBUS_ARRAY_MAX_LENGTH {
            return Err(DbusParseError::ArrayLengthOverflow);
        }

        let mut res = Vec::with_capacity(inner_len + 4);

        res.append(&mut DbusUint32::marshal(
            (inner_len as u32).into(),
            endianness,
        )?);

        let alignment = std::cmp::max(Self::ALIGNMENT, T::ALIGNMENT);
        if alignment > Self::ALIGNMENT {
            res.extend(vec![0; alignment - Self::ALIGNMENT]);
        };

        res.append(&mut inner_marshalled);

        Ok(res)
        unimplemented!()
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
        let (buf, inner) = signature.parse_buffer(buf, endianness)?;
        if inner.len() != 2 {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        let mut iter = inner.into_iter();
        let v1 = iter.next().unwrap().into();
        let v2 = iter.next().unwrap().into();

        Ok((buf, Self(v1, v2)))
    }

    fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
        unimplemented!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DbusDict(Vec<DbusDictEntry>);

impl DbusDict {
    #[allow(dead_code)]
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

    fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
        unimplemented!()
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
