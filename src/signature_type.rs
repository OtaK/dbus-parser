use crate::types::basic::*;
use crate::header::components::MessageEndianness;
use crate::{DbusTypeContainer, DbusType};
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

/*impl SignatureType {
    fn create_parser<I, O: DbusType>(&self) -> Option<impl Fn(I, Option<MessageEndianness>) -> nom::IResult<I, O>> {
        match self {
            SignatureType::Invalid => None,
            SignatureType::Boolean => Some(DbusBoolean::parse),
            SignatureType::Byte => Some(DbusByte::parse),
            SignatureType::Uint16 => Some(DbusUint16::parse),
            SignatureType::Int16 => Some(DbusInt16::parse),
            SignatureType::Uint32 => Some(DbusUint32::parse),
            SignatureType::Int32 => Some(DbusInt32::parse),
            SignatureType::Uint64 => Some(DbusUint64::parse),
            SignatureType::Int64 => Some(DbusInt64::parse),
            SignatureType::Double => Some(DbusDouble::parse),
            #[cfg(unix)]
            SignatureType::UnixFd => Some(DbusUnixFd::parse),
            SignatureType::Signature => Some(DbusSignature::parse),
            SignatureType::String => Some(DbusString::parse),
            SignatureType::ObjectPath => Some(DbusObjectPath::parse),
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
}*/


 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature<'a>(&'a [SignatureType]);

impl<'a> Signature<'a> {
    pub fn new(signature: &'a [SignatureType]) -> Self {
        Signature(signature)
    }
}

impl Signature<'_> {
    fn parse_buffer(&self, buf: &[u8], endianness: Option<MessageEndianness>) -> IResult<&[u8], &[DbusTypeContainer]> {
        //self.0.iter().fold(buf, move |buf, signature_type| {
            unimplemented!()
        //})
    }
}
