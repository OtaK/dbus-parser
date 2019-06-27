use crate::types::basic::*;
use crate::DbusType;

macro_rules! impl_from_iresult_type {
    ($container:ty, $variant:expr, $type:ty) => {
        impl From<$type> for $container {
            fn from(v: $type) -> Self {
                $variant(v)
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
}

impl DbusTypeContainer {
    pub fn map_from<I, T: DbusType>((i, t): (I, T)) -> (I, Self) where Self: From<T> {
        (i, Self::from(t))
    }
}

impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Boolean, DbusBoolean);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Byte, DbusByte);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Uint16, DbusUint16);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Int16, DbusInt16);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Uint32, DbusUint32);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Int32, DbusInt32);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Uint64, DbusUint64);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Int64, DbusInt64);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Double, DbusDouble);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::UnixFd, DbusUnixFd);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::Signature, DbusSignature);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::String, DbusString);
impl_from_iresult_type!(DbusTypeContainer, DbusTypeContainer::ObjectPath, DbusObjectPath);
