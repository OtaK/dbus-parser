use crate::header::components::MessageEndianness;
use crate::signature_type::Signature;
use crate::type_container::DbusTypeContainer;
use crate::DbusType;
use nom::combinator::iterator;
use nom::IResult;

#[derive(Debug, Clone, PartialEq)]
pub struct DbusStruct(Vec<DbusTypeContainer>);

impl DbusType for DbusStruct {
    const ALIGNMENT: usize = 8;

    fn parse<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        signature: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let (buf, inner) = signature.parse_buffer(buf, endianness, signature)?;
        Ok((buf, Self(inner)))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DbusDictEntry((DbusTypeContainer, DbusTypeContainer));

impl DbusType for DbusDictEntry {
    const ALIGNMENT: usize = 8;

    fn parse<'a, 'b>(
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

        Ok((buf, Self((v1, v2))))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DbusDict(Vec<DbusDictEntry>);

impl DbusType for DbusDict {
    const ALIGNMENT: usize = 8;

    fn parse<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        signature: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let mut it = iterator(buf, |buf| DbusDictEntry::parse(buf, endianness, signature));

        let inner = it.collect();
        let (buf, _) = it.finish()?;

        Ok((buf, Self(inner)))
    }
}
