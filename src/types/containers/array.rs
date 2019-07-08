use crate::error::DbusParseError;
use crate::header::components::MessageEndianness;
use crate::signature_type::Signature;
use crate::types::basic::DbusUint32;
use crate::DbusType;
use nom::bytes::streaming::take;
use nom::combinator::iterator;
use nom::combinator::map;
use nom::number::streaming::be_u32;
use nom::number::streaming::le_u32;
use nom::IResult;

#[derive(Debug, Clone, PartialEq)]
pub struct DbusArray<T: DbusType>(Vec<T>);

impl<T: DbusType> DbusType for DbusArray<T> {
    const ALIGNMENT: usize = 4;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        signature: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let (buf, len) = match endianness {
            MessageEndianness::BigEndian => map(be_u32, |v| v as usize)(buf),
            MessageEndianness::LittleEndian => map(le_u32, |v| v as usize)(buf),
        }?;

        let inner_alignment = T::ALIGNMENT;
        // Advance buffer by discarding bytes to pad alignment
        let (buf, _) = take(std::cmp::max(Self::ALIGNMENT, inner_alignment))(buf)?;

        let mut it = iterator(buf, |buf| T::unmarshal(buf, endianness, signature));
        let inner: Vec<T> = it.collect();
        let (buf, _) = it.finish()?;

        if inner.len() % len != 0 {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        Ok((buf, Self(inner)))
    }

    fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
        let items_count = self.0.len();
        let mut inner_marshalled = self.0.into_iter().try_fold(
            Vec::with_capacity(items_count * T::ALIGNMENT),
            |mut buf, current_entry| {
                buf.extend(current_entry.marshal(endianness)?);
                Ok(buf)
            },
        )?;
        let inner_len = inner_marshalled.len();
        let mut res = Vec::with_capacity(inner_len + 4);
        res.append(&mut DbusUint32::marshal(
            (inner_len as u32).into(),
            endianness,
        )?);
        res.append(&mut inner_marshalled);

        Ok(res)
    }
}
