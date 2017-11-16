//! Errors happening when dealing with domain names.
//!
//! Since many of them are used in more than one module, and there is
//! excessive `From` conversions between them, we collect them all here.

use std::{error, fmt};
use bytes::Bytes;
use ::bits::error::ShortBuf;
use super::label::Label;


//------------ DnameError ----------------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnameError {
    /// An unsupported label type was encountered.
    BadLabel(LabelTypeError),

    /// A compression pointer was encountered.
    CompressedName,

    /// The byte slice was too short.
    ShortData,

    /// There was data after the root label.
    TrailingData,

    /// The name was longer than 255 bytes.
    LongName,

    /// The name didn’t end with the root label.
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

impl error::Error for DnameError {
    fn description(&self) -> &str {
        use self::DnameError::*;

        match *self {
            BadLabel(ref err) => err.description(),
            CompressedName => "compressed domain name",
            ShortData => "short data",
            TrailingData => "trailing data",
            LongName => "long domain name",
            RelativeName => "relative domain name",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        use self::DnameError::*;

        match *self {
            BadLabel(ref err) => Some(err),
            _ => None
        }
    }
}

impl fmt::Display for DnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    UnexpectedEnd,

    /// An empty label was encountered.
    EmptyLabel,

    /// A binary label was encountered.
    BinaryLabel,

    /// A domain name label has more than 63 octets.
    LongLabel,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    IllegalCharacter,

    /// An absolute name was encountered.
    AbsoluteName,

    /// The name has more than 255 characters.
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

impl error::Error for FromStrError {
    fn description(&self) -> &str {
        use self::FromStrError::*;

        match *self {
            UnexpectedEnd => "unexpected end of input",
            EmptyLabel => "an empty label was encountered",
            BinaryLabel => "a binary label was encountered",
            LongLabel => "domain name label with more than 63 octets",
            IllegalEscape => "illegal escape sequence",
            IllegalCharacter => "illegal character",
            AbsoluteName => "absolute name",
            LongName => "domain name with more than 255 octets",
        }
    }
}

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//------------ IndexError ----------------------------------------------------

/// An index into a name did not indicate the start of a label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

impl error::Error for IndexError {
    fn description(&self) -> &str {
        "illegal index"
    }
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ LabelTypeError ------------------------------------------------

/// A bad label type was encountered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelTypeError {
    /// The label was of the undefined type `0b10`.
    Undefined,

    /// The label was of extended label type given.
    /// 
    /// The type value will be in the range `0x40` to `0x7F`, that is, it
    /// includes the original label type bits `0b01`.
    Extended(u8),
}

impl error::Error for LabelTypeError {
    fn description(&self) -> &str {
        use self::LabelTypeError::*;

        match *self {
            Undefined => "undefined label type",
            Extended(0x41) => "binary label",
            Extended(_) => "unknown extended label type",
        }
    }
}

impl fmt::Display for LabelTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::LabelTypeError::*;

        match *self {
            Undefined => f.write_str("undefined label type"),
            Extended(0x41) => f.write_str("binary label"),
            Extended(t) => write!(f, "extended label type 0x{:x}", t),
        }
    }
}


//------------ LongLabelError ------------------------------------------------

/// A label was longer than the allowed 63 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongLabelError;

impl error::Error for LongLabelError {
    fn description(&self) -> &str {
        "long label"
    }
}

impl fmt::Display for LongLabelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ LongNameError -------------------------------------------------

/// An attempt was made to strip a suffix that wasn’t actually a suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongNameError;

impl error::Error for LongNameError {
    fn description(&self) -> &str {
        "long domain name"
    }
}

impl fmt::Display for LongNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ ParsedDnameError ----------------------------------------------

/// An error happened when parsing a possibly compressed domain name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedDnameError {
    /// The parser ended before the name.
    ShortBuf,

    /// A bad label was encountered.
    BadLabel(LabelTypeError),

    /// The name is longer than the 255 bytes limit.
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

impl error::Error for ParsedDnameError {
    fn description(&self) -> &str {
        match *self {
            ParsedDnameError::ShortBuf => ShortBuf.description(),
            ParsedDnameError::BadLabel(ref err) => err.description(),
            ParsedDnameError::LongName => LongNameError.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ParsedDnameError::BadLabel(ref err) => Some(err),
            _ => None
        }
    }
}

impl fmt::Display for ParsedDnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParsedDnameError::BadLabel(ref err) => err.fmt(f),
            _ => f.write_str(error::Error::description(self))
        }
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while trying to push data to a domain name builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushError {
    /// The current label would exceed the limit of 63 bytes.
    LongLabel,

    /// The name would exceed the limit of 255 bytes.
    LongName,
}
 
impl error::Error for PushError {
    fn description(&self) -> &str {
        match *self {
            PushError::LongLabel => "label size exceeded",
            PushError::LongName => "name size exceeded",
        }
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ RelativeDnameError --------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelativeDnameError {
    /// A bad label was encountered.
    BadLabel(LabelTypeError),

    /// A compressed name was encountered.
    CompressedName,

    /// The data ended before the end of a label.
    ShortData,

    /// The domain name was longer than 255 octets.
    LongName,

    /// The root label was encountered.
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

impl error::Error for RelativeDnameError {
    fn description(&self) -> &str {
        use self::RelativeDnameError::*;

        match *self {
            BadLabel(ref err) => ::std::error::Error::description(err),
            CompressedName => "compressed domai name",
            ShortData => "short data",
            LongName => "long domain name",
            AbsoluteName => "absolute domain name",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        use self::RelativeDnameError::*;

        match *self {
            BadLabel(ref err) => Some(err),
            _ => None
        }
    }
}

impl fmt::Display for RelativeDnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;
        use self::RelativeDnameError::*;

        match *self {
            BadLabel(ref err) => err.fmt(f),
            _ => f.write_str(self.description())
        }
    }
}


//------------ RootNameError -------------------------------------------------

/// An attempt was made to remove labels from a name that is only the root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootNameError;

impl error::Error for RootNameError {
    fn description(&self) -> &str {
        "operation not allowed on root name"
    }
}

impl fmt::Display for RootNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ SplitLabelError -----------------------------------------------

/// An error happened while splitting a label from a bytes slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitLabelError {
    /// The label was a pointer to the given position.
    Pointer(u16),

    /// The label type was invalid.
    BadType(LabelTypeError),

    /// The bytes slice was too short.
    ShortSlice,
}

impl error::Error for SplitLabelError {
    fn description(&self) -> &str {
        use self::SplitLabelError::*;
        
        match *self {
            Pointer(_) => "compressed domain name",
            BadType(ref err) => err.description(),
            ShortSlice => "short domain name",
        }
    }
}

impl fmt::Display for SplitLabelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(::std::error::Error::description(self))
    }
}


//------------ StripSuffixError ----------------------------------------------

/// An attempt was made to strip a suffix that wasn’t actually a suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StripSuffixError;

impl error::Error for StripSuffixError {
    fn description(&self) -> &str {
        "suffix not found"
    }
}

impl fmt::Display for StripSuffixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "suffix not found".fmt(f)
    }
}

