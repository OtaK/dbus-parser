use crate::{
    error::DbusParseError,
    header::components::MessageEndianness,
    signature_type::Signature,
    DbusType,
};

use nom::{
    combinator::map,
    number::streaming::*,
    IResult,
};

macro_rules! __inner_marshal_get_bytes {
    ($self:ident, $endianness:ident, $align:expr) => {
        match $endianness {
            MessageEndianness::BigEndian => $self.0.to_be_bytes(),
            MessageEndianness::LittleEndian => $self.0.to_le_bytes(),
        }
    };

    (float $self:ident, $endianness:ident, $align:expr) => {{
        let bits = $self.0.to_bits();
        match $endianness {
            MessageEndianness::BigEndian => bits.to_be_bytes(),
            MessageEndianness::LittleEndian => bits.to_le_bytes(),
        }
    }};
}

macro_rules! __inner_impl_parsable {
    ($name:ident, $inner:ty, $mthd_le:ident, $mthd_be:ident, $align:expr) => {
        impl DbusType for $name {
            const ALIGNMENT: usize = $align;

            fn unmarshal<'a, 'b>(
                buf: &'b [u8],
                endianness: MessageEndianness,
                _: &'a Signature,
            ) -> IResult<&'b [u8], Self> {
                map(
                    match endianness {
                        MessageEndianness::BigEndian => $mthd_be,
                        MessageEndianness::LittleEndian => $mthd_le,
                    },
                    |v: $inner| $name(v),
                )(buf)
            }

            fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
                let mut res = Vec::with_capacity($align);
                let bytes = __inner_marshal_get_bytes!(self, endianness, $align);
                res.copy_from_slice(&bytes);
                Ok(res)
            }
        }
    };

    (float $name:ident, $inner:ty, $mthd_le:ident, $mthd_be:ident, $align:expr) => {
        impl DbusType for $name {
            const ALIGNMENT: usize = $align;

            fn unmarshal<'a, 'b>(
                buf: &'b [u8],
                endianness: MessageEndianness,
                _: &'a Signature,
            ) -> IResult<&'b [u8], Self> {
                map(
                    match endianness {
                        MessageEndianness::BigEndian => $mthd_be,
                        MessageEndianness::LittleEndian => $mthd_le,
                    },
                    |v: $inner| $name(v),
                )(buf)
            }

            fn marshal(self, endianness: MessageEndianness) -> Result<Vec<u8>, DbusParseError> {
                let mut res = Vec::with_capacity($align);
                let bytes = __inner_marshal_get_bytes!(float self, endianness, $align);
                res.copy_from_slice(&bytes);
                Ok(res)
            }
        }
    };
}

macro_rules! impl_parsable {
    ($name:ident, $inner:ty, $mthd_le:ident, $mthd_be:ident, $align:expr) => {
        /// A $inner integer wrapper
        #[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
        pub struct $name($inner);

        __inner_impl_parsable!($name, $inner, $mthd_le, $mthd_be, $align);

        impl From<$inner> for $name {
            fn from(v: $inner) -> Self {
                Self(v)
            }
        }

        impl Into<$inner> for $name {
            fn into(self) -> $inner {
                self.0
            }
        }
    };

    (float $name:ident, $inner:ty, $mthd_le:ident, $mthd_be:ident, $align:expr) => {
        /// A $inner integer wrapper
        #[derive(Debug, Clone, Default, Copy, PartialEq)]
        pub struct $name($inner);

        __inner_impl_parsable!(float $name, $inner, $mthd_le, $mthd_be, $align);

        impl From<$inner> for $name {
            fn from(v: $inner) -> Self {
                Self(v)
            }
        }

        impl Into<$inner> for $name {
            fn into(self) -> $inner {
                self.0
            }
        }
    };
}

impl_parsable!(DbusByte, u8, le_u8, be_u8, 1);
impl_parsable!(DbusUint16, u16, le_u16, be_u16, 2);
impl_parsable!(DbusInt16, i16, le_i16, be_i16, 2);
impl_parsable!(DbusUint32, u32, le_u32, be_u32, 4);
impl_parsable!(DbusInt32, i32, le_i32, be_i32, 4);
impl_parsable!(DbusUint64, u64, le_u64, be_u64, 8);
impl_parsable!(DbusInt64, i64, le_i64, be_i64, 8);
impl_parsable!(float DbusDouble, f64, le_f64, be_f64, 8);
impl_parsable!(DbusUnixFd, u32, le_u32, be_u32, 4);
