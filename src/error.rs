use failure_derive::Fail;

#[derive(Debug, Fail)]
pub enum DbusParseError {
    #[fail(display = "The provided endianness is invalid")]
    InvalidEndianness,
    #[fail(display = "The provided message type is invalid")]
    InvalidMessageType,
    #[fail(display = "The provided header field is invalid")]
    InvalidHeaderField,
    #[fail(display = "The provided object path is invalid")]
    MalformedObjectPath,
    #[fail(display = "Unknown error")]
    UnknownError,
}