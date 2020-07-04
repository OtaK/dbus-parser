use crate::{
    error::DbusParseError,
    header::components::MessageEndianness,
    signature_type::Signature,
    types::basic::DbusUint32,
    DbusType,
};
use nom::{
    bytes::streaming::take,
    combinator::iterator,
    combinator::map,
    number::streaming::be_u32,
    number::streaming::le_u32,
    IResult,
};
const DBUS_ARRAY_MAX_LENGTH: usize = 2 ^ 26;

#[derive(Debug, Clone, Default, PartialEq)]
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

        if len > DBUS_ARRAY_MAX_LENGTH {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        // Advance buffer by discarding bytes to pad alignment
        let alignment = std::cmp::max(Self::ALIGNMENT, T::ALIGNMENT);
        let pad = if alignment > Self::ALIGNMENT {
            alignment - Self::ALIGNMENT
        } else {
            0
        };
        let (buf, _) = take(pad)(buf)?;

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
    }
}
