use crate::header::components::MessageEndianness;
use crate::signature_type::Signature;
use crate::DbusParseError;
use crate::DbusType;
use core::convert::TryFrom;
use nom::bytes::streaming::*;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::number::streaming::{be_u32, le_u32};
use nom::IResult;

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DbusObjectPath(String);

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
