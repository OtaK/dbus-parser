use crate::header::components::MessageEndianness;
use crate::types::basic::*;
use crate::{DbusTypeContainer, DbusType};
use nom::IResult;

#[derive(Debug, Clone, PartialEq)]
pub struct DbusVariant {
    signature: DbusSignature,
    inner: DbusTypeContainer,
}

impl DbusType for DbusVariant {
    fn parse(buf: &[u8], endianness: Option<MessageEndianness>) -> IResult<&[u8], Self> {
        let (buf, signature) = DbusSignature::parse(buf, endianness)?;
        //let (buf, inner)

        unimplemented!()
    }
}
