pub mod components;

use crate::error::DbusParseError;
use crate::types::{containers::*, basic::*};
use self::components::*;
use crate::signature_type::{Signature, SignatureType};
use crate::DbusType;
use nom::branch::alt;
use nom::{
    combinator::{map, map_res},
    number::streaming::{be_u32, be_u8, le_u32, le_u8},
    sequence::tuple,
    *,
};
use std::convert::{TryFrom, TryInto};

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
    const ALIGNMENT: usize = 0;

    fn unmarshal<'a, 'b>(
        i: &'b [u8],
        _: MessageEndianness,
        _: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
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

#[derive(Debug, Clone, PartialEq)]
pub struct RawHeaderFields(std::collections::HashMap<HeaderField, DbusVariant>);

impl std::ops::Deref for RawHeaderFields {
    type Target = std::collections::HashMap<HeaderField, DbusVariant>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RawHeaderFields {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DbusType for RawHeaderFields {
    const ALIGNMENT: usize = 0;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        _: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let signature = Signature::new(vec![
            SignatureType::Array,
            SignatureType::DictStart,
            SignatureType::Byte,
            SignatureType::Variant,
            SignatureType::DictEnd,
        ]);
        let (buf, inner) = map_res(
            map(
                |buf| signature.parse_buffer(buf, endianness, &signature),
                DbusDict::from,
            ),
            DbusDict::try_into,
        )(buf)?;
        Ok((buf, Self(inner)))
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct HeaderFields {
    path: Option<DbusObjectPath>,
    interface: Option<DbusString>,
    member: Option<DbusString>,
    error_name: Option<DbusString>,
    reply_serial: Option<DbusUint32>,
    destination: Option<DbusString>,
    sender: Option<DbusString>,
    signature: Option<Signature>,
    unix_fds: Option<DbusUint32>
}

impl TryFrom<RawHeaderFields> for HeaderFields {
    type Error = DbusParseError;

    fn try_from(mut fields: RawHeaderFields) -> Result<Self, Self::Error> {
        let mut ret = Self::default();
        if let Some(path) = fields.remove(&HeaderField::Path).map(DbusVariant::into_inner) {
            ret.path = Some(DbusObjectPath::try_from(path)?);
        }

        if let Some(interface) = fields.remove(&HeaderField::Interface).map(DbusVariant::into_inner) {
            ret.interface = Some(DbusString::try_from(interface)?);
        }

        if let Some(member) = fields.remove(&HeaderField::Member).map(DbusVariant::into_inner) {
            ret.member = Some(DbusString::try_from(member)?);
        }

        if let Some(error_name) = fields.remove(&HeaderField::ErrorName).map(DbusVariant::into_inner) {
            ret.error_name = Some(DbusString::try_from(error_name)?);
        }

        if let Some(reply_serial) = fields.remove(&HeaderField::ReplySerial).map(DbusVariant::into_inner) {
            ret.reply_serial = Some(DbusUint32::try_from(reply_serial)?);
        }

        if let Some(destination) = fields.remove(&HeaderField::Destination).map(DbusVariant::into_inner) {
            ret.destination = Some(DbusString::try_from(destination)?);
        }

        if let Some(sender) = fields.remove(&HeaderField::Sender).map(DbusVariant::into_inner) {
            ret.sender = Some(DbusString::try_from(sender)?);
        }

        if let Some(signature) = fields.remove(&HeaderField::Signature).map(DbusVariant::into_inner) {
            ret.signature = Some(DbusSignature::try_from(signature)?.try_into()?);
        }

        if let Some(unix_fds) = fields.remove(&HeaderField::UnixFdCount).map(DbusVariant::into_inner) {
            ret.unix_fds = Some(DbusUint32::try_from(unix_fds)?);
        }

        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    fixed: FixedHeaderPart,
    fields: HeaderFields
}

impl DbusType for Header {
    const ALIGNMENT: usize = 0;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        e: MessageEndianness,
        s: &'a Signature,
    ) -> IResult<&'b [u8], Self> {
        let (buf, fixed) = FixedHeaderPart::unmarshal(buf, e, s)?;
        let (buf, fields) = map_res(|buf| RawHeaderFields::unmarshal(buf, fixed.endianness, s), HeaderFields::try_from)(buf)?;

        Ok((buf, Self {
            fixed,
            fields
        }))
    }
}
