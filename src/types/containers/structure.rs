use crate::{
    header::components::MessageEndianness,
    signature_type::Signature,
    type_container::DbusTypeContainer,
    {DbusParseError, DbusType},
};
use nom::{
    combinator::iterator,
    IResult,
};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

macro_rules! impl_marshal_struct {
    () => {
        fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
            let items_count = self.0.len();
            let res = self.0.into_iter().try_fold(
                Vec::with_capacity(items_count * Self::ALIGNMENT),
                |mut buf, current_entry| {
                    let mut entry_bytes = current_entry.marshal(endianness)?;
                    let pad = entry_bytes.len() % Self::ALIGNMENT;
                    if pad > 0 {
                        entry_bytes.extend(vec![0; pad]);
                    }

                    buf.extend(entry_bytes);
                    Ok(buf)
                },
            )?;

            Ok(res)
        }
    };
}

#[derive(Debug, Clone, Default, PartialEq)]
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

    impl_marshal_struct!();
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
        let mut buf = self.0.marshal(endianness)?;
        let pad = buf.len() % Self::ALIGNMENT;
        if pad > 0 {
            buf.extend(vec![0; pad]);
        }

        buf.extend(self.1.marshal(endianness)?);
        let pad = buf.len() % Self::ALIGNMENT;
        if pad > 0 {
            buf.extend(vec![0; pad]);
        }

        Ok(buf)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
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

    impl_marshal_struct!();
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
