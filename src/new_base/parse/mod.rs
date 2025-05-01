//! Parsing DNS messages from the wire format.
//!
//! At the moment, a high-level or mid-level API for parsing DNS messages is
//! not implemented.  This section documents the low-level API.
//!
//! This example shows how to parse a practical DNS message.
//!
//! ```
//! # use domain::new_base::*;
//! # use domain::new_base::name::RevNameBuf;
//! # use domain::new_base::parse::*;
//! # use domain::new_rdata::{RecordData, A};
//! # use domain::new_edns::*;
//! #
//! // The bytes to be parsed.
//! let bytes = [
//!     // The message header.
//!     0, 42, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1,
//!     // A question: www.example.org. A IN
//!     3, b'w', b'w', b'w',
//!     7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
//!     3, b'o', b'r', b'g', 0,
//!     0, 1, 0, 1,
//!     // An answer: www.example.org. A IN 3600 127.0.0.1
//!     192, 12, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 127, 0, 0, 1,
//!     // An OPT record.
//!     0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 12,
//!       // An EDNS client cookie.
//!       0, 10, 0, 8, 6, 148, 57, 104, 176, 18, 234, 57,
//! ];
//!
//! // Parse the top-level message structure, in place.
//! let message: &Message = <&Message>::parse_bytes(&bytes).unwrap();
//!
//! assert_eq!(message.header.id.get(), 42);
//! assert!(!message.header.flags.qr());
//! assert!(message.header.flags.rd());
//! assert_eq!(message.header.counts.questions.get(), 1);
//! assert_eq!(message.header.counts.answers.get(), 1);
//! assert_eq!(message.header.counts.authorities.get(), 0);
//! assert_eq!(message.header.counts.additionals.get(), 1);
//!
//! // Prepare to traverse the message.
//! let mut offset = 0usize;
//!
//! // Parse the question.
//! let question;
//! (question, offset) = <Question<RevNameBuf>>
//!     ::split_message_bytes(&message.contents, offset).unwrap();
//!
//! assert_eq!(question.qname, "www.example.org".parse().unwrap());
//! assert_eq!(question.qtype, QType::A);
//! assert_eq!(question.qclass, QClass::IN);
//!
//! // Parse the answer.
//! println!("answer at {offset}");
//! let answer;
//! (answer, offset) = <Record<RevNameBuf, RecordData<'_, RevNameBuf>>>
//!     ::split_message_bytes(&message.contents, offset).unwrap();
//!
//! assert_eq!(answer.rname, "www.example.org".parse().unwrap());
//! assert_eq!(answer.rtype, RType::A);
//! assert_eq!(answer.rclass, RClass::IN);
//! assert_eq!(answer.ttl.value.get(), 3600);
//! assert_eq!(answer.rdata, RecordData::A("127.0.0.1".parse().unwrap()));
//!
//! // Parse the OPT record.
//! println!("opt at {offset}");
//! let opt;
//! (opt, offset) = <Record<RevNameBuf, RecordData<'_, RevNameBuf>>>
//!     ::split_message_bytes(&message.contents, offset).unwrap();
//!
//! assert_eq!(opt.rtype, RType::OPT);
//! let opt: EdnsRecord<'_> = opt.try_into().unwrap();
//!
//! assert_eq!(opt.max_udp_payload.get(), 1232);
//! assert_eq!(opt.ext_rcode, 0);
//! assert_eq!(opt.version, 0);
//! assert!(opt.flags.is_dnssec_ok());
//!
//! // Parse EDNS options in the OPT record.
//! let mut options = opt.options.options();
//!
//! let option: EdnsOption<'_> = options.next().unwrap().unwrap();
//! let EdnsOption::ClientCookie(cookie) = option else { panic!() };
//! assert_eq!(cookie.octets, [6, 148, 57, 104, 176, 18, 234, 57]);
//!
//! assert_eq!(options.next(), None);
//!
//! // Finish parsing the message.
//! assert_eq!(offset, message.contents.len());
//! ```

use core::mem::MaybeUninit;

pub use super::wire::{
    ParseBytes, ParseBytesZC, ParseError, SplitBytes, SplitBytesZC,
};

//----------- ParseMessageBytes ----------------------------------------------

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

#[cfg(feature = "alloc")]
impl<'a, T: ParseMessageBytes<'a>> ParseMessageBytes<'a>
    for alloc::boxed::Box<T>
{
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        T::parse_message_bytes(contents, start).map(alloc::boxed::Box::new)
    }
}

#[cfg(feature = "alloc")]
impl<'a> ParseMessageBytes<'a> for alloc::vec::Vec<u8> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        contents.get(start..).map(|s| s.to_vec()).ok_or(ParseError)
    }
}

#[cfg(feature = "alloc")]
impl<'a> ParseMessageBytes<'a> for alloc::string::String {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        <&str>::parse_message_bytes(contents, start).map(|s| s.into())
    }
}

//----------- SplitMessageBytes ----------------------------------------------

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

#[cfg(feature = "alloc")]
impl<'a, T: SplitMessageBytes<'a>> SplitMessageBytes<'a>
    for alloc::boxed::Box<T>
{
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        T::split_message_bytes(contents, start)
            .map(|(this, rest)| (alloc::boxed::Box::new(this), rest))
    }
}
