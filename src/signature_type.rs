use nom::combinator::map_res;
use crate::error::DbusParseError;
use crate::header::components::MessageEndianness;
use crate::types::basic::*;
use crate::{DbusType, DbusTypeContainer};
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureType {
    Invalid = 0x00,
    Boolean = b'b',
    Byte = b'y',
    Uint16 = b'q',
    Int16 = b'n',
    Uint32 = b'u',
    Int32 = b'i',
    Uint64 = b't',
    Int64 = b'x',
    Double = b'f',
    UnixFd = b'h',
    Signature = b'g',
    String = b's',
    ObjectPath = b'o',
    Array = b'a',
    Variant = b'v',
    StructStart = b'(',
    StructEnd = b')',
    DictStart = b'{',
    DictEnd = b'}',
    GVariant = b'm',
    SingleCompleteType = b'*',
    BasicType = b'?',
    GVariantType = b'@',
    GVariantPointer = b'&',
    GVariantConversion = b'^',
}

impl TryFrom<u8> for SignatureType {
    type Error = DbusParseError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(SignatureType::Invalid),
            b'b' => Ok(SignatureType::Boolean),
            b'y' => Ok(SignatureType::Byte),
            b'q' => Ok(SignatureType::Uint16),
            b'n' => Ok(SignatureType::Int16),
            b'u' => Ok(SignatureType::Uint32),
            b'i' => Ok(SignatureType::Int32),
            b't' => Ok(SignatureType::Uint64),
            b'x' => Ok(SignatureType::Int64),
            b'f' => Ok(SignatureType::Double),
            b'h' => Ok(SignatureType::UnixFd),
            b'g' => Ok(SignatureType::Signature),
            b's' => Ok(SignatureType::String),
            b'o' => Ok(SignatureType::ObjectPath),
            b'a' => Ok(SignatureType::Array),
            b'v' => Ok(SignatureType::Variant),
            b'(' => Ok(SignatureType::StructStart),
            b')' => Ok(SignatureType::StructEnd),
            b'{' => Ok(SignatureType::DictStart),
            b'}' => Ok(SignatureType::DictEnd),
            b'm' => Ok(SignatureType::GVariant),
            b'*' => Ok(SignatureType::SingleCompleteType),
            b'?' => Ok(SignatureType::BasicType),
            b'@' => Ok(SignatureType::GVariantType),
            b'&' => Ok(SignatureType::GVariantPointer),
            b'^' => Ok(SignatureType::GVariantConversion),
            _ => Err(DbusParseError::InvalidSignature),
        }
    }
}

impl SignatureType {
    fn parse_buffer<'a>(
        &self,
        buf: &'a [u8],
        endianness: MessageEndianness,
        signature: &Signature,
    ) -> Option<nom::IResult<&'a [u8], DbusTypeContainer>> {
        match self {
            SignatureType::Boolean => Some(
                map_res(|buf| DbusBoolean::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Byte => Some(
                map_res(|buf| DbusByte::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Uint16 => Some(
                map_res(|buf| DbusUint16::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Int16 => Some(
                map_res(|buf| DbusInt16::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Uint32 => Some(
                map_res(|buf| DbusUint32::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Int32 => Some(
                map_res(|buf| DbusInt32::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Uint64 => Some(
                map_res(|buf| DbusUint64::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Int64 => Some(
                map_res(|buf| DbusInt64::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Double => Some(
                map_res(|buf| DbusDouble::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::UnixFd => Some(
                map_res(|buf| DbusUnixFd::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Signature => Some(
                map_res(|buf| DbusSignature::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::String => Some(
                map_res(|buf| DbusString::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::ObjectPath => Some(
                map_res(|buf| DbusObjectPath::unmarshal(buf, endianness, signature), DbusTypeContainer::try_from)(buf),
            ),
            SignatureType::Array => unimplemented!(),
            SignatureType::Variant => unimplemented!(),
            SignatureType::StructStart => unimplemented!(),
            SignatureType::DictStart => unimplemented!(),
            SignatureType::GVariant => unimplemented!(),
            SignatureType::GVariantType => unimplemented!(),
            SignatureType::GVariantPointer => unimplemented!(),
            SignatureType::GVariantConversion => unimplemented!(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signature(Vec<SignatureType>);

impl Signature {
    pub fn new(signature: Vec<SignatureType>) -> Self {
        Signature(signature)
    }
}

impl std::ops::Deref for Signature {
    type Target = Vec<SignatureType>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Signature {
    pub fn parse_buffer<'a>(
        &self,
        buf: &'a [u8],
        endianness: MessageEndianness,
        signature: &Signature,
    ) -> nom::IResult<&'a [u8], Vec<DbusTypeContainer>> {
        let init = (buf, Vec::with_capacity(self.0.len()));
        self.0
            .iter()
            .try_fold(init, move |(buf, mut ret), signature_type| {
                if let Some(parse_result) = signature_type.parse_buffer(buf, endianness, signature)
                {
                    let (buf, container) = parse_result?;
                    ret.push(container);
                    Ok((buf, ret))
                } else {
                    Ok((buf, ret))
                }
            })
    }
}
