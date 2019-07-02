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
    #[fail(display = "The signature type is invalid")]
    InvalidSignature,
    #[fail(
        display = "The type transformation is invalid, the container holds a different variant than the target"
    )]
    InvalidContainerVariantTarget,
    #[fail(display = "Unknown error")]
    UnknownError,
}
