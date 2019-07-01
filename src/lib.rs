use crate::header::components::MessageEndianness;
use nom::IResult;

mod error;
mod header;
mod signature_type;

mod type_container;
mod types;
pub use self::error::*;
pub use self::header::*;
pub use self::signature_type::*;
pub use self::type_container::*;

pub trait DbusType: std::fmt::Debug + Clone + PartialEq {
    const ALIGNMENT: usize;

    fn unmarshal<'a, 'b>(
        buf: &'b [u8],
        endianness: MessageEndianness,
        signature: &'a Signature,
    ) -> IResult<&'b [u8], Self>;
}
