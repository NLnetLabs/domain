//! A domain name that can be both relative or absolute.

use std::str;
use super::builder::DnameBuilder;
use super::dname::Dname;
use super::error::FromStrError;
use super::relative::RelativeDname;


//------------ UncertainDname ------------------------------------------------

/// A domain name that may be absolute or relative.
///
/// This type is helpful when reading a domain name from some source where it
/// may end up being absolute or not.
#[derive(Clone, Debug)]
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
                _ => return Err(FromStrError::IllegalCharacter)
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


