use crate::{
    header::components::MessageEndianness,
    signature_type::Signature,
    types::basic::DbusUint32,
    DbusParseError,
    DbusType,
};
use core::convert::TryFrom;
use nom::{
    bytes::streaming::*,
    combinator::map,
    combinator::map_res,
    number::streaming::{be_u32, le_u32},
    IResult,
};

macro_rules! impl_string_parse {
    ($target:ty) => {
        impl DbusType for $target {
            const ALIGNMENT: usize = 4;

            fn unmarshal<'a, 'b>(
                buf: &'b [u8],
                endianness: MessageEndianness,
                _: &'a Signature,
            ) -> IResult<&'b [u8], Self> {
                let (buf, len) = match endianness {
                    MessageEndianness::BigEndian => map(be_u32, |v| v as usize)(buf),
                    MessageEndianness::LittleEndian => map(le_u32, |v| v as usize)(buf),
                }?;

                let (buf, s) = map_res(
                    map(map_res(take(len), std::str::from_utf8), String::from),
                    Self::try_from,
                )(buf)?;

                if s.0.len() != len {
                    return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
                }

                let pad = 1 + ((len + 1) % Self::ALIGNMENT);

                let (buf, rest) = take(pad)(buf)?;
                if rest.len() != 1 || rest[0] != b'\0' {
                    return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
                }

                Ok((buf, s))
            }

            fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
                let string_len = self.0.len();
                let alloc_len = string_len + 5;
                let mut res = Vec::with_capacity(alloc_len);
                res.append(&mut DbusUint32::marshal(
                    (string_len as u32).into(),
                    endianness,
                )?);
                res.append(&mut self.0.into_bytes());
                res.push(b'\0');
                Ok(res)
            }
        }
    };
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DbusString(String);
impl_string_parse!(DbusString);

impl From<String> for DbusString {
    fn from(v: String) -> Self {
        Self(v)
    }
}

impl Into<String> for DbusString {
    fn into(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DbusObjectPath(String);

impl TryFrom<DbusString> for DbusObjectPath {
    type Error = DbusParseError;

    fn try_from(value: DbusString) -> Result<Self, Self::Error> {
        let s: String = value.into();
        Self::try_from(s)
    }
}

impl TryFrom<String> for DbusObjectPath {
    type Error = DbusParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // The path must begin with an ASCII '/' (integer 47) character, and must consist of elements separated by slash characters.
        if !value.starts_with("/") {
            return Err(DbusParseError::MalformedObjectPath);
        }

        // A trailing '/' character is not allowed unless the path is the root path (a single '/' character).
        if value.len() == 1 {
            return Ok(DbusObjectPath(value.into()));
        }

        if let Err(_) = value
            .split("/")
            .try_fold((), |_, fragment| -> Result<(), DbusParseError> {
                // No element may be the empty string.
                if fragment.len() == 0 {
                    return Err(DbusParseError::UnknownError);
                }

                // Each element must only contain the ASCII characters "[A-Z][a-z][0-9]_"
                if fragment
                    .as_bytes()
                    .iter()
                    .position(|b| {
                        (*b >= b'A' && *b <= b'Z')
                            || (*b >= b'a' && *b <= b'z')
                            || (*b >= b'0' && *b <= b'9')
                            || *b == b'_'
                    })
                    .is_none()
                {
                    return Err(DbusParseError::UnknownError);
                }

                Ok(())
            })
        {
            return Err(DbusParseError::MalformedObjectPath);
        }

        Ok(DbusObjectPath(value))
    }
}

impl_string_parse!(DbusObjectPath);
