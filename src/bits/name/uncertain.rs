//! A domain name that can be both relative or absolute.

use std::{fmt, str};
use bytes::BufMut;
use ::bits::compose::Compose;
use ::master::error::ScanError;
use ::master::scan::{CharSource, Scan, Scanner, Symbol};
use super::builder::{DnameBuilder, PushError};
use super::chain::{Chain, LongChainError};
use super::dname::Dname;
use super::relative::{DnameIter, RelativeDname};
use super::traits::{ToDname, ToLabelIter};


//------------ UncertainDname ------------------------------------------------

/// A domain name that may be absolute or relative.
///
/// This type is helpful when reading a domain name from some source where it
/// may end up being absolute or not.
#[derive(Clone)]
pub enum UncertainDname {
    Absolute(Dname),
    Relative(RelativeDname),
}

impl UncertainDname {
    /// Creates a new uncertain domain name from an absolute domain name.
    pub fn absolute(name: Dname) -> Self {
        UncertainDname::Absolute(name)
    }

    /// Creates a new uncertain domain name from a relative domain name.
    pub fn relative(name: RelativeDname) -> Self {
        UncertainDname::Relative(name)
    }

    pub fn root() -> Self {
        UncertainDname::Absolute(Dname::root())
    }

    pub fn empty() -> Self {
        UncertainDname::Relative(RelativeDname::empty())
    }

    /// Creates a domain name from a sequence of characters.
    ///
    /// The sequence must result in a domain name in master format
    /// representation. That is, its labels should be separated by dots,
    /// actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// If the last character is a dot, the name will be absolute, otherwise
    /// it will be relative.
    ///
    /// If you have a string, you can also use the `FromStr` trait, which
    /// really does the same thing.
    pub fn from_chars<C>(chars: C) -> Result<Self, FromStrError>
                      where C: IntoIterator<Item=char> {
        Self::_from_chars(chars.into_iter(), DnameBuilder::new())
    }

    /// Does the actual work for `from_chars` and `FromStr::from_str`.
    fn _from_chars<C>(mut chars: C, mut target: DnameBuilder)
                      -> Result<Self, FromStrError>
                   where C: Iterator<Item=char> {
        while let Some(ch) = chars.next() {
            match ch {
                '.' => {
                    if !target.in_label() {
                        return Err(FromStrError::EmptyLabel)
                    }
                    target.end_label();
                }
                '\\' => {
                    let in_label = target.in_label();
                    target.push(parse_escape(&mut chars, in_label)?)?;
                }
                ' ' ... '-' | '/' ... '[' | ']' ... '~' => {
                    target.push(ch as u8)?
                }
                _ => return Err(FromStrError::IllegalCharacter(ch))
            }
        }
        if target.in_label() || target.is_empty() {
            Ok(target.finish().into())
        }
        else {
            target.into_dname().map(Into::into)
                               .map_err(|_| FromStrError::LongName)
        }
    }

    /// Returns whether the name is absolute.
    pub fn is_absolute(&self) -> bool {
        match *self {
            UncertainDname::Absolute(_) => true,
            UncertainDname::Relative(_) => false,
        }
    }

    /// Returns whether the name is relative.
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    /// Returns a reference to an absolute name, if this name is absolute.
    pub fn try_as_absolute(&self) -> Option<&Dname> {
        match *self {
            UncertainDname::Absolute(ref name) => Some(name),
            _ => None
        }
    }

    /// Returns a reference to a relative name, if the name is relative.
    pub fn try_as_relative(&self) -> Option<&RelativeDname> {
        match *self {
            UncertainDname::Relative(ref name) => Some(name),
            _ => None,
        }
    }

    /// Converts the name into an absolute name if it is absolute.
    ///
    /// Otherwise, returns itself as the error.
    pub fn try_into_absolute(self) -> Result<Dname, Self> {
        if let UncertainDname::Absolute(name) = self {
            Ok(name)
        }
        else {
            Err(self)
        }
    }

    /// Converts the name into a relative name if it is relative.
    ///
    /// Otherwise just returns itself as the error.
    pub fn try_into_relative(self) -> Result<RelativeDname, Self> {
        if let UncertainDname::Relative(name) = self {
            Ok(name)
        }
        else {
            Err(self)
        }
    }

    /// Converts the name into an absolute name.
    ///
    /// If the name is relative, appends the root label to it using
    /// [`RelativeDname::into_absolute`].
    ///
    /// [`RelativeDname::into_absolute`]:
    ///     struct.RelativeDname.html#method.into_absolute
    pub fn into_absolute(self) -> Dname {
        match self {
            UncertainDname::Absolute(name) => name,
            UncertainDname::Relative(name) => name.into_absolute()
        }
    }

    pub fn chain<S: ToDname>(self, suffix: S)
                             -> Result<Chain<Self, S>, LongChainError> {
        Chain::new_uncertain(self, suffix)
    }
}


//--- Compose

impl Compose for UncertainDname {
    fn compose_len(&self) -> usize {
        match *self {
            UncertainDname::Absolute(ref name) => name.compose_len(),
            UncertainDname::Relative(ref name) => name.compose_len(),
        }
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        match *self {
            UncertainDname::Absolute(ref name) => name.compose(buf),
            UncertainDname::Relative(ref name) => name.compose(buf),
        }
    }
}


//--- From

impl From<Dname> for UncertainDname {
    fn from(name: Dname) -> Self {
        Self::absolute(name)
    }
}

impl From<RelativeDname> for UncertainDname {
    fn from(name: RelativeDname) -> Self {
        Self::relative(name)
    }
}


//--- FromStr

impl str::FromStr for UncertainDname {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::_from_chars(s.chars(), DnameBuilder::with_capacity(s.len()))
    }
}


//--- Scan

impl Scan for UncertainDname {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_word(
            DnameBuilder::new(),
            |name, symbol| {
                match symbol {
                    Symbol::Char('.') => {
                        if name.in_label() {
                            name.end_label();
                        }
                        else {
                            return Err(FromStrError::EmptyLabel.into())
                        }
                    }
                    Symbol::Char(ch) | Symbol::SimpleEscape(ch) => {
                        if ch.is_ascii() {
                            if let Err(err) = name.push(ch as u8) {
                                return Err(FromStrError::from(err).into())
                            }
                        }
                        else {
                            return Err(FromStrError::IllegalCharacter(ch)
                                                    .into())
                        }
                    }
                    Symbol::DecimalEscape(ch) => {
                        if let Err(err) = name.push(ch) {
                            return Err(FromStrError::from(err).into())
                        }
                    }
                }
                Ok(())
            },
            |name| {
                if name.in_label() || name.is_empty() {
                    Ok(name.finish().into())
                }
                else {
                    name.into_dname()
                        .map(Into::into)
                        .map_err(|err| FromStrError::from(err).into())
                }
            }
        )
    }
}


//--- ToLabelIter

impl<'a> ToLabelIter<'a> for UncertainDname {
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        match *self {
            UncertainDname::Absolute(ref name) => name.iter_labels(),
            UncertainDname::Relative(ref name) => name.iter_labels(),
        }
    }
}


//--- Display and Debug

impl fmt::Display for UncertainDname {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UncertainDname::Absolute(ref name) => name.fmt(f),
            UncertainDname::Relative(ref name) => name.fmt(f),
        }
    }
}

impl fmt::Debug for UncertainDname {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UncertainDname::Absolute(ref name) => {
                write!(f, "UncertainDname::Absolute({})", name)
            }
            UncertainDname::Relative(ref name) => {
                write!(f, "UncertainDname::Relative({})", name)
            }
        }
    }
}


//------------ Santa’s Little Helpers ----------------------------------------

/// Parses the contents of an escape sequence from `chars`.
///
/// The backslash should already have been taken out of `chars`.
fn parse_escape<C>(chars: &mut C, in_label: bool) -> Result<u8, FromStrError>
                where C: Iterator<Item=char> {
    let ch = try!(chars.next().ok_or(FromStrError::UnexpectedEnd));
    if ch == '0' || ch == '1' || ch == '2' {
        let v = ch.to_digit(10).unwrap() * 100
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)))
                     * 10
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)));
        Ok(v as u8)
    }
    else if ch == '[' {
        // `\[` at the start of a label marks a binary label which we don’t
        // support. Within a label, the sequence is fine.
        if in_label {
            Ok(b'[')
        }
        else {
            Err(FromStrError::BinaryLabel)
        }
    }
    else { Ok(ch as u8) }
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
    #[fail(display="illegal character '{}'", _0)]
    IllegalCharacter(char),

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

