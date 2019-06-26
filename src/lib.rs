use nom::IResult;

mod error;
mod header;
mod signature_type;
mod types;

pub use self::error::*;
pub use self::header::*;
pub use self::signature_type::*;
use self::types::basic::*;

pub trait DbusType: std::fmt::Debug + Clone + PartialEq {
    fn parse(
        buf: &[u8],
        endianness: Option<header::components::MessageEndianness>,
    ) -> IResult<&[u8], Self>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum DbusTypeContainer {
    Byte(DbusByte),
    Uint16(DbusUint16),
    Int16(DbusInt16),
    Uint32(DbusUint32),
    Int32(DbusInt32),
    Uint64(DbusUint64),
    Int64(DbusInt64),
    Double(DbusDouble),
    #[cfg(unix)]
    UnixFd(DbusUnixFd),
    Signature(DbusSignature),
    String(DbusString),
    ObjectPath(DbusObjectPath),
}
