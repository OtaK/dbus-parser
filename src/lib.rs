use nom::IResult;

mod error;
mod header;
mod types;

pub use self::error::*;
pub use self::header::*;

pub trait Parsable {
    fn parse(
        buf: &[u8],
        endianness: Option<header::components::MessageEndianness>,
    ) -> IResult<&[u8], Self>
    where
        Self: Sized;
}
