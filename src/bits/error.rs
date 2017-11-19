//! Cross-module error types.


//------------ ShortParser ---------------------------------------------------

/// An attempt was made to go beyond the end of a buffer.
#[derive(Clone, Debug, Eq, Fail, PartialEq)]
#[fail(display="unexpected end of buffer")]
pub struct ShortBuf;

