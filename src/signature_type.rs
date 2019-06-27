
use crate::error::DbusParseError;
use crate::header::components::MessageEndianness;
use crate::types::basic::*;
use crate::{DbusType, DbusTypeContainer};
use core::convert::TryFrom;

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
        endianness: Option<MessageEndianness>,
    ) -> Option<nom::IResult<&'a [u8], DbusTypeContainer>> {
        match self {
            SignatureType::Boolean => {
                Some(DbusBoolean::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Byte => {
                Some(DbusByte::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Uint16 => {
                Some(DbusUint16::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Int16 => {
                Some(DbusInt16::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Uint32 => {
                Some(DbusUint32::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Int32 => {
                Some(DbusInt32::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Uint64 => {
                Some(DbusUint64::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Int64 => {
                Some(DbusInt64::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Double => {
                Some(DbusDouble::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::UnixFd => {
                Some(DbusUnixFd::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::Signature => {
                Some(DbusSignature::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::String => {
                Some(DbusString::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
            SignatureType::ObjectPath => {
                Some(DbusObjectPath::parse(buf, endianness).map(DbusTypeContainer::map_from))
            }
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
    #[allow(dead_code)]
    fn parse_buffer<'a>(
        &self,
        buf: &'a [u8],
        endianness: Option<MessageEndianness>,
    ) -> nom::IResult<&'a [u8], Vec<DbusTypeContainer>> {
        let init = (buf, Vec::with_capacity(self.0.len()));
        self.0
            .iter()
            .try_fold(init, move |(buf, mut ret), signature_type| {
                if let Some(parse_result) = signature_type.parse_buffer(buf, endianness) {
                    let (buf, container) = parse_result?;
                    ret.push(container);
                    Ok((buf, ret))
                } else {
                    Ok((buf, ret))
                }
            })
    }
}
