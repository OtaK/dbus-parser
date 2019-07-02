use crate::types::{basic::*, containers::*};
use crate::DbusParseError;
use std::convert::TryFrom;

macro_rules! impl_from_iresult_type {
    ($container:ident, $variant:ident, $type:ident) => {
        impl TryFrom<$type> for $container {
            type Error = DbusParseError;
            fn try_from(v: $type) -> Result<Self, Self::Error> {
                Ok($container::$variant(v))
            }
        }

        impl TryFrom<$container> for $type {
            type Error = DbusParseError;
            fn try_from(v: $container) -> Result<Self, Self::Error> {
                match v {
                    $container::$variant(v) => Ok(v),
                    _ => Err(DbusParseError::InvalidContainerVariantTarget),
                }
            }
        }
    };

    (box $container:ident, $variant:ident, $type:ident) => {
        impl TryFrom<$type> for $container {
            type Error = DbusParseError;
            fn try_from(v: $type) -> Result<Self, Self::Error> {
                Ok($container::$variant(Box::new(v)))
            }
        }

        impl TryFrom<$container> for $type {
            type Error = DbusParseError;

            fn try_from(v: $container) -> Result<Self, Self::Error> {
                match v {
                    $container::$variant(v) => Ok(*v),
                    _ => Err(DbusParseError::InvalidContainerVariantTarget),
                }
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq)]
pub enum DbusTypeContainer {
    Boolean(DbusBoolean),
    Byte(DbusByte),
    Uint16(DbusUint16),
    Int16(DbusInt16),
    Uint32(DbusUint32),
    Int32(DbusInt32),
    Uint64(DbusUint64),
    Int64(DbusInt64),
    Double(DbusDouble),
    UnixFd(DbusUnixFd),
    Signature(DbusSignature),
    String(DbusString),
    ObjectPath(DbusObjectPath),
    Variant(Box<DbusVariant>),
}

impl_from_iresult_type!(DbusTypeContainer, Boolean, DbusBoolean);
impl_from_iresult_type!(DbusTypeContainer, Byte, DbusByte);
impl_from_iresult_type!(DbusTypeContainer, Uint16, DbusUint16);
impl_from_iresult_type!(DbusTypeContainer, Int16, DbusInt16);
impl_from_iresult_type!(DbusTypeContainer, Uint32, DbusUint32);
impl_from_iresult_type!(DbusTypeContainer, Int32, DbusInt32);
impl_from_iresult_type!(DbusTypeContainer, Uint64, DbusUint64);
impl_from_iresult_type!(DbusTypeContainer, Int64, DbusInt64);
impl_from_iresult_type!(DbusTypeContainer, Double, DbusDouble);
impl_from_iresult_type!(DbusTypeContainer, UnixFd, DbusUnixFd);
impl_from_iresult_type!(DbusTypeContainer, Signature, DbusSignature);
impl_from_iresult_type!(DbusTypeContainer, String, DbusString);
impl_from_iresult_type!(DbusTypeContainer, ObjectPath, DbusObjectPath);
impl_from_iresult_type!(box DbusTypeContainer, Variant, DbusVariant);
