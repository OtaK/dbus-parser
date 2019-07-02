use crate::error::DbusParseError;
use crate::type_container::DbusTypeContainer;
use crate::types::basic::DbusByte;
use bitflags::bitflags;
use std::convert::{TryFrom, TryInto};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageEndianness {
    LittleEndian = b'l',
    BigEndian = b'B',
}

impl Default for MessageEndianness {
    fn default() -> Self {
        MessageEndianness::LittleEndian
    }
}

impl std::convert::TryFrom<u8> for MessageEndianness {
    type Error = DbusParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            b'l' => Ok(MessageEndianness::LittleEndian),
            b'B' => Ok(MessageEndianness::BigEndian),
            _ => Err(DbusParseError::InvalidEndianness),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Invalid = 0x00,
    MethodCall = 0x01,
    MethodReturn = 0x02,
    Error = 0x03,
    Signal = 0x04,
}

impl Default for MessageType {
    fn default() -> Self {
        MessageType::Invalid
    }
}

impl std::convert::TryFrom<u8> for MessageType {
    type Error = DbusParseError;

    fn try_from(value: u8) -> Result<Self, DbusParseError> {
        match value {
            0x01 => Ok(MessageType::MethodCall),
            0x02 => Ok(MessageType::MethodReturn),
            0x03 => Ok(MessageType::Error),
            0x04 => Ok(MessageType::Signal),
            _ => Err(DbusParseError::InvalidMessageType),
        }
    }
}

bitflags! {
    #[derive(Default)]
    pub struct MessageFlags: u8 {
        const NO_REPLY_EXPECTED = 1 << 1;
        const NO_AUTO_START = 1 << 2;
        const ALLOW_INTERACTIVE_AUTHORIZATION = 1 << 3;
    }
}

impl From<u8> for MessageFlags {
    fn from(value: u8) -> Self {
        MessageFlags::from_bits_truncate(value)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum HeaderField {
    Invalid = 0x00,
    Path = 0x01,
    Interface = 0x02,
    Member = 0x03,
    ErrorName = 0x04,
    ReplySerial = 0x05,
    Destination = 0x06,
    Sender = 0x07,
    Signature = 0x08,
    UnixFdCount = 0x09,
}

impl Default for HeaderField {
    fn default() -> Self {
        HeaderField::Invalid
    }
}

impl TryFrom<u8> for HeaderField {
    type Error = DbusParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(HeaderField::Path),
            0x02 => Ok(HeaderField::Interface),
            0x03 => Ok(HeaderField::Member),
            0x04 => Ok(HeaderField::ErrorName),
            0x05 => Ok(HeaderField::ReplySerial),
            0x06 => Ok(HeaderField::Destination),
            0x07 => Ok(HeaderField::Sender),
            0x08 => Ok(HeaderField::Signature),
            0x09 => Ok(HeaderField::UnixFdCount),
            _ => Err(DbusParseError::InvalidHeaderField),
        }
    }
}

impl TryFrom<DbusByte> for HeaderField {
    type Error = DbusParseError;

    fn try_from(value: DbusByte) -> Result<Self, Self::Error> {
        let value: u8 = value.into();
        Self::try_from(value)
    }
}

impl TryFrom<DbusTypeContainer> for HeaderField {
    type Error = DbusParseError;

    fn try_from(value: DbusTypeContainer) -> Result<Self, Self::Error> {
        let b: DbusByte = value.try_into()?;
        Self::try_from(b)
    }
}
