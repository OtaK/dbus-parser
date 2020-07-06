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
                Ok(match endianness {
                    MessageEndianness::BigEndian => self.0.to_be_bytes(),
                    MessageEndianness::LittleEndian => self.0.to_le_bytes(),
                }.into())
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
                let bits = self.0.to_bits();
                Ok(match endianness {
                    MessageEndianness::BigEndian => bits.to_be_bytes(),
                    MessageEndianness::LittleEndian => bits.to_le_bytes(),
                }.into())
            }
        }
    };
}

macro_rules! impl_parsable {
    ($name:ident, $sig:expr, $inner:ty, $mthd_le:ident, $mthd_be:ident, $align:expr, $test_mod:ident, $t_mthd_marsh:ident, $t_mthd_unmarsh:ident) => {
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

        test_parsable!($name, $sig, $inner, $test_mod, $t_mthd_marsh, $t_mthd_unmarsh);
    };

    (float $name:ident, $sig:expr, $inner:ty, $mthd_le:ident, $mthd_be:ident, $align:expr, $test_mod:ident, $t_mthd_marsh:ident, $t_mthd_unmarsh:ident) => {
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

        test_parsable!($name, $sig, $inner, $test_mod, $t_mthd_marsh, $t_mthd_unmarsh);
    };
}

macro_rules! test_parsable {
    ($typ:ident, $sig:expr, $inner:ty, $mod_name:ident, $t_mthd_marsh:ident, $t_mthd_unmarsh:ident) => {
        #[cfg(test)]
        mod $mod_name {
            use super::*;
            use crate::signature_type::SignatureType;

            #[test]
            fn $t_mthd_marsh() {
                let num = rand::random::<$inner>();
                let v = $typ::from(num);
                assert_eq!(num.to_le_bytes(), *v.marshal(MessageEndianness::LittleEndian).unwrap());
                assert_eq!(num.to_be_bytes(), *v.marshal(MessageEndianness::BigEndian).unwrap());
            }

            #[test]
            fn $t_mthd_unmarsh() {
                let v = rand::random::<$inner>();
                let v_le = v.to_le_bytes();
                let v_be = v.to_be_bytes();
                $typ::unmarshal(&v_le, MessageEndianness::LittleEndian, &$sig.into()).unwrap();
                $typ::unmarshal(&v_be, MessageEndianness::BigEndian, &$sig.into()).unwrap();
            }
        }
    };
}

impl_parsable!(DbusByte, SignatureType::Byte, u8, le_u8, be_u8, 1, test_du8, test_marshal_du8, test_unmarshal_du8);
impl_parsable!(DbusUint16, SignatureType::Uint16, u16, le_u16, be_u16, 2, test_du16, test_marshal_du16, test_unmarshal_du16);
impl_parsable!(DbusInt16, SignatureType::Int16, i16, le_i16, be_i16, 2, test_di16, test_marshal_di16, test_unmarshal_di16);
impl_parsable!(DbusUint32, SignatureType::Uint32, u32, le_u32, be_u32, 4, test_du32, test_marshal_du32, test_unmarshal_du32);
impl_parsable!(DbusInt32, SignatureType::Int32, i32, le_i32, be_i32, 4, test_di32, test_marshal_di32, test_unmarshal_di32);
impl_parsable!(DbusUint64, SignatureType::Uint64, u64, le_u64, be_u64, 8, test_du64, test_marshal_du64, test_unmarshal_du64);
impl_parsable!(DbusInt64, SignatureType::Int64, i64, le_i64, be_i64, 8, test_di64, test_marshal_di64, test_unmarshal_di64);
impl_parsable!(float DbusDouble, SignatureType::Double, f64, le_f64, be_f64, 8, test_ddouble, test_marshal_ddouble, test_unmarshal_ddouble);
impl_parsable!(DbusUnixFd, SignatureType::UnixFd, u32, le_u32, be_u32, 4, test_dunixfd, test_marshal_dunixfd, test_unmarshal_dunixfd);
