pub mod components;

use self::components::*;
use crate::DbusType;
use nom::branch::alt;
use nom::{
    combinator::{map, map_res},
    number::streaming::{be_u32, be_u8, le_u32, le_u8},
    sequence::tuple,
    *,
};
use std::convert::TryFrom;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FixedHeaderPart {
    pub endianness: MessageEndianness,
    pub message_type: MessageType,
    pub flags: MessageFlags,
    pub protocol_version: u8,
    pub msg_len: u32,
    pub msg_serial: u32,
}

impl DbusType for FixedHeaderPart {
    fn parse(i: &[u8], _: Option<MessageEndianness>) -> IResult<&[u8], Self> {
        let (i, endianness) = map_res(alt((le_u8, be_u8)), MessageEndianness::try_from)(i)?;

        let (i, (message_type, flags, protocol_version, msg_len, msg_serial)) = match endianness {
            MessageEndianness::BigEndian => tuple((
                map_res(be_u8, MessageType::try_from),
                map(be_u8, MessageFlags::from),
                be_u8,
                be_u32,
                be_u32,
            ))(i)?,
            MessageEndianness::LittleEndian => tuple((
                map_res(le_u8, MessageType::try_from),
                map(le_u8, MessageFlags::from),
                le_u8,
                le_u32,
                le_u32,
            ))(i)?,
        };

        Ok((
            i,
            FixedHeaderPart {
                endianness,
                message_type,
                flags,
                protocol_version,
                msg_serial,
                msg_len,
            },
        ))
    }
}

//#[derive(Debug, Copy, Clone, Eq, PartialEq)]
//pub struct HeaderFields(std::collections::HashMap<HeaderField, Variant>);