//! Parsing DNS messages from the wire format.
//!
//! This module provides [`ParseMessageBytes`] and [`SplitMessageBytes`],
//! which are specializations of [`ParseBytes`] and [`SplitBytes`] to DNS
//! messages.  When parsing data within a DNS message, these traits allow
//! access to all preceding bytes in the message so that compressed names can
//! be resolved.
//!
//! [`ParseBytes`]: super::wire::ParseBytes
//! [`SplitBytes`]: super::wire::SplitBytes

use core::mem::MaybeUninit;

pub use super::wire::ParseError;

use super::wire::{ParseBytes, ParseBytesZC, SplitBytes, SplitBytesZC};

//----------- Message parsing traits -----------------------------------------

/// A type that can be parsed from bytes in a DNS message.
pub trait ParseMessageBytes<'a>: ParseBytes<'a> {
    /// Parse a value from bytes in a DNS message.
    ///
    /// The contents of the DNS message (up to and including the actual bytes
    /// to be parsed) is provided as `contents`.  The 12-byte message header
    /// is not included.  `contents[start..]` is the input to be parsed.  The
    /// earlier bytes are provided for resolving compressed domain names.
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError>;
}

impl<'a> ParseMessageBytes<'a> for u8 {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        match contents.get(start..) {
            Some(&[b]) => Ok(b),
            _ => Err(ParseError),
        }
    }
}

impl<'a, T: ?Sized + ParseBytesZC> ParseMessageBytes<'a> for &'a T {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        T::parse_bytes_by_ref(&contents[start..])
    }
}

impl<'a, T: SplitMessageBytes<'a>, const N: usize> ParseMessageBytes<'a>
    for [T; N]
{
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        match <[T; N]>::split_message_bytes(contents, start) {
            Ok((this, rest)) if rest == contents.len() => Ok(this),
            _ => Err(ParseError),
        }
    }
}

#[cfg(feature = "std")]
impl<'a, T: ParseMessageBytes<'a>> ParseMessageBytes<'a>
    for std::boxed::Box<T>
{
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        T::parse_message_bytes(contents, start).map(std::boxed::Box::new)
    }
}

#[cfg(feature = "std")]
impl<'a> ParseMessageBytes<'a> for std::vec::Vec<u8> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        contents.get(start..).map(|s| s.to_vec()).ok_or(ParseError)
    }
}

#[cfg(feature = "std")]
impl<'a> ParseMessageBytes<'a> for std::string::String {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        <&str>::parse_message_bytes(contents, start).map(|s| s.into())
    }
}

/// A type that can be parsed from a DNS message.
pub trait SplitMessageBytes<'a>:
    SplitBytes<'a> + ParseMessageBytes<'a>
{
    /// Parse a value from the start of a byte sequence within a DNS message.
    ///
    /// The contents of the DNS message (i.e. without the 12-byte header) is
    /// provided as `contents`.  `contents[start..]` is the beginning of the
    /// input to be parsed.  The earlier bytes are provided for resolving
    /// compressed domain names.
    ///
    /// If parsing is successful, the parsed value and the offset for the rest
    /// of the input are returned.  If `len` bytes were parsed to form `self`,
    /// `start + len` should be the returned offset.
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError>;
}

impl<'a> SplitMessageBytes<'a> for u8 {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        contents
            .get(start)
            .map(|&b| (b, start + 1))
            .ok_or(ParseError)
    }
}

impl<'a, T: ?Sized + SplitBytesZC> SplitMessageBytes<'a> for &'a T {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        T::split_bytes_by_ref(&contents[start..])
            .map(|(this, rest)| (this, contents.len() - rest.len()))
    }
}

impl<'a, T: SplitMessageBytes<'a>, const N: usize> SplitMessageBytes<'a>
    for [T; N]
{
    fn split_message_bytes(
        contents: &'a [u8],
        mut start: usize,
    ) -> Result<(Self, usize), ParseError> {
        // TODO: Rewrite when either 'array_try_map' or 'try_array_from_fn'
        // is stabilized.

        /// A guard for dropping initialized elements on panic / failure.
        struct Guard<T, const N: usize> {
            /// The array of elements being built up.
            buffer: [MaybeUninit<T>; N],

            /// The number of elements currently initialized.
            initialized: usize,
        }

        impl<T, const N: usize> Drop for Guard<T, N> {
            fn drop(&mut self) {
                for elem in &mut self.buffer[..self.initialized] {
                    // SAFETY: The first 'initialized' elems are initialized.
                    unsafe { elem.assume_init_drop() };
                }
            }
        }

        let mut guard = Guard::<T, N> {
            buffer: [const { MaybeUninit::uninit() }; N],
            initialized: 0,
        };

        while guard.initialized < N {
            let (elem, rest) = T::split_message_bytes(contents, start)?;
            guard.buffer[guard.initialized].write(elem);
            start = rest;
            guard.initialized += 1;
        }

        // Disable the guard since we're moving data out now.
        guard.initialized = 0;

        // SAFETY: '[MaybeUninit<T>; N]' and '[T; N]' have the same layout,
        // because 'MaybeUninit<T>' and 'T' have the same layout, because it
        // is documented in the standard library.
        Ok((unsafe { core::mem::transmute_copy(&guard.buffer) }, start))
    }
}

#[cfg(feature = "std")]
impl<'a, T: SplitMessageBytes<'a>> SplitMessageBytes<'a>
    for std::boxed::Box<T>
{
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        T::split_message_bytes(contents, start)
            .map(|(this, rest)| (std::boxed::Box::new(this), rest))
    }
}
