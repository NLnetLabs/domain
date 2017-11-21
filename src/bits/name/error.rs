//! Errors happening when dealing with domain names.
//!
//! Since many of them are used in more than one module, and there is
//! excessive `From` conversions between them, we collect them all here.

use bytes::Bytes;
use ::bits::error::ShortBuf;
use super::label::Label;


//------------ DnameError ----------------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum DnameError {
    #[fail(display="{}", _0)]
    BadLabel(LabelTypeError),

    #[fail(display="compressed domain name")]
    CompressedName,

    #[fail(display="short data")]
    ShortData,

    #[fail(display="trailing data")]
    TrailingData,

    #[fail(display="long domain name")]
    LongName,

    #[fail(display="relative domain name")]
    RelativeName,
}

impl From<ShortBuf> for DnameError {
    fn from(_: ShortBuf) -> Self {
        DnameError::ShortData
    }
}

impl From<SplitLabelError> for DnameError {
    fn from(err: SplitLabelError) -> Self {
        match err {
            SplitLabelError::Pointer(_) => DnameError::CompressedName,
            SplitLabelError::BadType(t) => DnameError::BadLabel(t),
            SplitLabelError::ShortSlice => DnameError::ShortData,
        }
    }
}


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    #[fail(display="unexpected end of input")]
    UnexpectedEnd,

    /// An empty label was encountered.
    #[fail(display="an empty label was encountered")]
    EmptyLabel,

    /// A binary label was encountered.
    #[fail(display="a binary label was encountered")]
    BinaryLabel,

    /// A domain name label has more than 63 octets.
    #[fail(display="label length limit exceeded")]
    LongLabel,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    #[fail(display="illegal escape sequence")]
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    #[fail(display="illegal character")]
    IllegalCharacter,

    /// The name has more than 255 characters.
    #[fail(display="long domain name")]
    LongName,
}

impl From<PushError> for FromStrError {
    fn from(err: PushError) -> FromStrError {
        match err {
            PushError::LongLabel => FromStrError::LongLabel,
            PushError::LongName => FromStrError::LongName,
        }
    }
}


//------------ IndexError ----------------------------------------------------

/// An index into a name did not indicate the start of a label.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="illegal index")]
pub struct IndexError;

impl IndexError {
    pub(super) fn check(bytes: &Bytes, mut index: usize) -> Result<(), Self> {
        let mut tmp = bytes.as_ref();
        while !tmp.is_empty() {
            let (label, tail) = Label::split_from(tmp).unwrap();
            let len = label.len() + 1;
            if index < len {
                return Err(IndexError)
            }
            else if index == len {
                return Ok(())
            }
            index -= len;
            tmp = tail;
        }
        assert!(index == 0, "index exceeded length");
        Ok(())
    }
}


//------------ LabelTypeError ------------------------------------------------

/// A bad label type was encountered.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum LabelTypeError {
    /// The label was of the undefined type `0b10`.
    #[fail(display="undefined label type")]
    Undefined,

    /// The label was of extended label type given.
    /// 
    /// The type value will be in the range `0x40` to `0x7F`, that is, it
    /// includes the original label type bits `0b01`.
    #[fail(display="unknown extended label 0x{:02x}", _0)]
    Extended(u8),
}


//------------ LongLabelError ------------------------------------------------

/// A label was longer than the allowed 63 bytes.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="long label")]
pub struct LongLabelError;


//------------ LongNameError -------------------------------------------------

/// An attempt was made to strip a suffix that wasn’t actually a suffix.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="long domain name")]
pub struct LongNameError;


//------------ ParsedDnameError ----------------------------------------------

/// An error happened when parsing a possibly compressed domain name.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParsedDnameError {
    /// The parser ended before the name.
    #[fail(display="unexpected end of buffer")]
    ShortBuf,

    /// A bad label was encountered.
    #[fail(display="{}", _0)]
    BadLabel(LabelTypeError),

    /// The name is longer than the 255 bytes limit.
    #[fail(display="long domain name")]
    LongName,
}

impl From<ShortBuf> for ParsedDnameError {
    fn from(_: ShortBuf) -> ParsedDnameError {
        ParsedDnameError::ShortBuf
    }
}

impl From<LabelTypeError> for ParsedDnameError {
    fn from(err: LabelTypeError) -> ParsedDnameError {
        ParsedDnameError::BadLabel(err)
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while trying to push data to a domain name builder.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum PushError {
    /// The current label would exceed the limit of 63 bytes.
    #[fail(display="long label")]
    LongLabel,

    /// The name would exceed the limit of 255 bytes.
    #[fail(display="long domain name")]
    LongName,
}


//------------ RelativeDnameError --------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum RelativeDnameError {
    /// A bad label was encountered.
    #[fail(display="{}", _0)]
    BadLabel(LabelTypeError),

    /// A compressed name was encountered.
    #[fail(display="compressed domain name")]
    CompressedName,

    /// The data ended before the end of a label.
    #[fail(display="unexpected end of input")]
    ShortData,

    /// The domain name was longer than 255 octets.
    #[fail(display="long domain name")]
    LongName,

    /// The root label was encountered.
    #[fail(display="absolute domain name")]
    AbsoluteName,
}

impl From<SplitLabelError> for RelativeDnameError {
    fn from(err: SplitLabelError) -> Self {
        match err {
            SplitLabelError::Pointer(_) => RelativeDnameError::CompressedName,
            SplitLabelError::BadType(t) => RelativeDnameError::BadLabel(t),
            SplitLabelError::ShortSlice => RelativeDnameError::ShortData,
        }
    }
}


//------------ RootNameError -------------------------------------------------

/// An attempt was made to remove labels from a name that is only the root.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="operation not allowed on root name")]
pub struct RootNameError;


//------------ SplitLabelError -----------------------------------------------

/// An error happened while splitting a label from a bytes slice.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum SplitLabelError {
    /// The label was a pointer to the given position.
    #[fail(display="compressed domain name")]
    Pointer(u16),

    /// The label type was invalid.
    #[fail(display="{}", _0)]
    BadType(LabelTypeError),

    /// The bytes slice was too short.
    #[fail(display="unexpected end of input")]
    ShortSlice,
}


//------------ StripSuffixError ----------------------------------------------

/// An attempt was made to strip a suffix that wasn’t actually a suffix.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="suffix not found")]
pub struct StripSuffixError;

