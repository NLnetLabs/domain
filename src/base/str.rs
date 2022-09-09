//! Support for converting from and to strings.
//!
//! This module contains helper types for converting from and to string
//! representation of types.

use core::{borrow, cmp, fmt, hash, ops, str};

//------------ String --------------------------------------------------------

/// An immutable, UTF-8 encoded string atop some octets sequence.
#[derive(Clone)]
pub struct String<Octets>(Octets);

impl<Octets> String<Octets> {
    /// Converts a sequence of octets into a string.
    pub fn from_utf8(octets: Octets) -> Result<Self, FromUtf8Error<Octets>>
    where
        Octets: AsRef<[u8]>,
    {
        if let Err(error) = str::from_utf8(octets.as_ref()) {
            Err(FromUtf8Error { octets, error })
        } else {
            Ok(String(octets))
        }
    }

    /// Converts a sequence of octets into a string without checking.
    ///
    /// # Safety
    ///
    /// The caller must make sure that octets is a sequence of correctly
    /// encoded UTF-8 characters. Otherwise, the use of the returned value
    /// is undefined.
    pub unsafe fn from_utf8_unchecked(octets: Octets) -> Self {
        String(octets)
    }

    /// Converts the string into its raw octets.
    pub fn into_octets(self) -> Octets {
        self.0
    }

    /// Returns the string as a string slice.
    pub fn as_str(&self) -> &str
    where
        Octets: AsRef<[u8]>,
    {
        unsafe { str::from_utf8_unchecked(self.0.as_ref()) }
    }

    /// Returns the string’s octets as a slice.
    pub fn as_slice(&self) -> &[u8]
    where
        Octets: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Returns the length of the string in octets.
    pub fn len(&self) -> usize
    where
        Octets: AsRef<[u8]>,
    {
        self.0.as_ref().len()
    }

    /// Returns whether the string is empty.
    pub fn is_empty(&self) -> bool
    where
        Octets: AsRef<[u8]>,
    {
        self.0.as_ref().is_empty()
    }
}

//--- Deref, AsRef, Borrow

impl<Octets: AsRef<[u8]>> ops::Deref for String<Octets> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl<Octets: AsRef<[u8]>> AsRef<str> for String<Octets> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for String<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octets: AsRef<[u8]>> borrow::Borrow<str> for String<Octets> {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<Octets: AsRef<[u8]>> borrow::Borrow<[u8]> for String<Octets> {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

//--- Debug and Display

impl<Octets: AsRef<[u8]>> fmt::Debug for String<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for String<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Other> for String<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<str>,
{
    fn eq(&self, other: &Other) -> bool {
        self.as_str().eq(other.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Eq for String<Octets> {}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for String<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state)
    }
}

//--- PartialOrd and Ord

impl<Octets, Other> PartialOrd<Other> for String<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<str>,
{
    fn partial_cmp(&self, other: &Other) -> Option<cmp::Ordering> {
        self.as_str().partial_cmp(other.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Ord for String<Octets> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

//============ Error Types ===================================================

//------------ FromUtf8Error -------------------------------------------------

/// An error happened when converting octets into a string.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FromUtf8Error<Octets> {
    octets: Octets,
    error: str::Utf8Error,
}

impl<Octets> FromUtf8Error<Octets> {
    /// Returns an octets slice of the data that failed to convert.
    pub fn as_slice(&self) -> &[u8]
    where
        Octets: AsRef<[u8]>,
    {
        self.octets.as_ref()
    }

    /// Returns the octets sequence that failed to convert.
    pub fn into_octets(self) -> Octets {
        self.octets
    }

    /// Returns the reason for the conversion error.
    pub fn utf8_error(&self) -> str::Utf8Error {
        self.error
    }
}

impl<Octets> fmt::Debug for FromUtf8Error<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FromUtf8Error")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<Octets> fmt::Display for FromUtf8Error<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

#[cfg(feature = "std")]
impl<Octets> std::error::Error for FromUtf8Error<Octets> {}
