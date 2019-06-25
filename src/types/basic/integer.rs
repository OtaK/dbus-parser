use crate::header::components::MessageEndianness;
use crate::Parsable;
use nom::combinator::map;
use nom::number::streaming::*;
use nom::IResult;

macro_rules! __inner_impl_parsable {
    ($name:ident, $inner:ty, $mthd_le:ident, $mthd_be:ident) => {
        impl Parsable for $name {
            fn parse(buf: &[u8], e: Option<MessageEndianness>) -> IResult<&[u8], Self> {
                map(
                    e.map(|e| match e {
                        MessageEndianness::BigEndian => $mthd_be,
                        MessageEndianness::LittleEndian => $mthd_le,
                    })
                    .unwrap_or_else(|| $mthd_le),
                    |v: $inner| $name(v),
                )(buf)
            }
        }
    };
}

macro_rules! impl_parsable {
    ($name:ident, $inner:ty, $mthd_le:ident, $mthd_be:ident) => {
        /// A $inner integer wrapper
        #[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
        pub struct $name($inner);

        __inner_impl_parsable!($name, $inner, $mthd_le, $mthd_be);
    };

    (noeq $name:ident, $inner:ty, $mthd_le:ident, $mthd_be:ident) => {
        /// A $inner integer wrapper
        #[derive(Debug, Clone, Default, Copy, PartialEq)]
        pub struct $name($inner);

        __inner_impl_parsable!($name, $inner, $mthd_le, $mthd_be);
    };
}

impl_parsable!(DbusByte, u8, le_u8, be_u8);
impl_parsable!(DbusUint16, u16, le_u16, be_u16);
impl_parsable!(DbusInt16, i16, le_i16, be_i16);

impl_parsable!(DbusUint32, u32, le_u32, be_u32);
impl_parsable!(Int32, i32, le_i32, be_i32);

impl_parsable!(DbusUint64, u64, le_u64, be_u64);
impl_parsable!(DbusInt64, i64, le_i64, be_i64);

impl_parsable!(noeq DbusDouble, f64, le_f64, be_f64);

#[cfg(unix)]
impl_parsable!(DbusUnixFd, u32, le_u32, be_u32);
