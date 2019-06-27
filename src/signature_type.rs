
use crate::header::components::MessageEndianness;
use crate::types::basic::*;
use crate::{DbusType, DbusTypeContainer};
use nom::IResult;

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

impl SignatureType {
    fn parse_buffer<'a>(
        &self,
        buf: &'a [u8],
        endianness: Option<MessageEndianness>,
    ) -> Option<nom::IResult<&'a [u8], DbusTypeContainer>> {
        match self {
            SignatureType::Invalid => None,
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
            SignatureType::StructEnd => None,
            SignatureType::DictStart => unimplemented!(),
            SignatureType::DictEnd => None,
            SignatureType::GVariant => unimplemented!(),
            SignatureType::SingleCompleteType => unimplemented!(),
            SignatureType::BasicType => unimplemented!(),
            SignatureType::GVariantType => unimplemented!(),
            SignatureType::GVariantPointer => unimplemented!(),
            SignatureType::GVariantConversion => unimplemented!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<SignatureType>);

impl Signature {
    pub fn new(signature: Vec<SignatureType>) -> Self {
        Signature(signature)
    }
}

impl Signature {
    #[allow(dead_code)]
    fn parse_buffer<'a>(
        &self,
        buf: &'a [u8],
        endianness: Option<MessageEndianness>,
    ) -> IResult<&'a [u8], Vec<DbusTypeContainer>> {
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
