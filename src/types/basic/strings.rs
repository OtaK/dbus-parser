use crate::header::components::MessageEndianness;
use crate::DbusParseError;
use crate::DbusType;
use core::convert::TryFrom;
use nom::bytes::streaming::*;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::number::streaming::{be_u32, le_u32};
use nom::IResult;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DbusString(String);

impl DbusType for DbusString {
    fn parse(buf: &[u8], e: Option<MessageEndianness>) -> IResult<&[u8], Self> {
        let (buf, len) =
            match e.ok_or_else(|| nom::Err::Failure((buf, nom::error::ErrorKind::Verify)))? {
                MessageEndianness::BigEndian => be_u32(buf),
                MessageEndianness::LittleEndian => le_u32(buf),
            }?;

        let (buf, s) = map_res(take(len), std::str::from_utf8)(buf)?;
        if s.len() != len as usize {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        let (buf, nul) = take(1usize)(buf)?;
        if nul.len() != 1 || nul[0] != b'\0' {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        Ok((buf, Self(s.into())))
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

impl DbusType for DbusObjectPath {
    fn parse(buf: &[u8], e: Option<MessageEndianness>) -> IResult<&[u8], Self> {
        let (buf, len) =
            match e.ok_or_else(|| nom::Err::Failure((buf, nom::error::ErrorKind::Verify)))? {
                MessageEndianness::BigEndian => be_u32(buf),
                MessageEndianness::LittleEndian => le_u32(buf),
            }?;

        let (buf, s) = map_res(
            map(map_res(take(len), std::str::from_utf8), String::from),
            Self::try_from,
        )(buf)?;

        if s.0.len() != len as usize {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        let (buf, nul) = take(1usize)(buf)?;
        if nul.len() != 1 || nul[0] != b'\0' {
            return Err(nom::Err::Error((buf, nom::error::ErrorKind::Verify)));
        }

        Ok((buf, s))
    }
}
