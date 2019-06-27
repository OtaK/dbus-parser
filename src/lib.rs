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
    fn parse(
        buf: &[u8],
        endianness: Option<header::components::MessageEndianness>,
    ) -> IResult<&[u8], Self>;
}
