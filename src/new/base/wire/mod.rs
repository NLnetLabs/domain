//! Low-level byte serialization.
//!
//! This is a low-level module providing simple and efficient mechanisms to
//! parse data from and build data into byte sequences.  It takes inspiration
//! from the [zerocopy] crate, but 1) is significantly simpler, 2) has simple
//! requirements for its `derive` macros, and 3) supports parsing out-of-place
//! (i.e. non-zero-copy).
//!
//! [zerocopy]: https://github.com/google/zerocopy
//!
//! # Design
//!
//! When a type is defined to represent a component of a network packet, its
//! internal structure should match the structure of its wire format.  Here's
//! an example of a question in a DNS message:
//!
//! ```
//! # use domain::new::base::{QType, QClass, wire::*};
//! #[derive(BuildBytes, ParseBytes, SplitBytes)]
//! pub struct Question<N> {
//!     /// The domain name being requested.
//!     pub qname: N,
//!
//!     /// The type of the requested records.
//!     pub qtype: QType,
//!
//!     /// The class of the requested records.
//!     pub qclass: QClass,
//! }
//! ```
//!
//! This exactly matches the structure of a question on the wire -- the QNAME,
//! the QTYPE, and the QCLASS.  This allows the definition of the type to also
//! specify the wire format concisely.
//!
//! Now, this type can be read from and written to bytes very easily:
//!
//! ```
//! # use domain::new::base::{Question, QType, QClass, name::RevNameBuf, wire::*};
//! // { qname: "org.", qtype: A, qclass: IN }
//! let bytes = [3, 111, 114, 103, 0, 0, 1, 0, 1];
//!
//! // Parse into a new 'Question'.
//! let question = Question::<RevNameBuf>::parse_bytes(&bytes).unwrap();
//! assert_eq!(question.qname, "org".parse::<RevNameBuf>().unwrap());
//! assert_eq!(question.qtype, QType::A);
//! assert_eq!(question.qclass, QClass::IN);
//!
//! // Build the question back into bytes.
//! let mut duplicate = [0u8; 9];
//! let rest = question.build_bytes(&mut duplicate).unwrap();
//! assert_eq!(*rest, []);
//! assert_eq!(bytes, duplicate);
//! ```
//!
//! There are three important traits to consider:
//!
//! - [`ParseBytes`]: For interpreting an entire byte string as an instance of
//!   the target type.
//!
//! - [`SplitBytes`]: For interpreting _the start_ of a byte string as an
//!   instance of the target type.
//!
//! - [`BuildBytes`]: For serializing an object and writing it to the _start_
//!   of a byte string.
//!
//! These operate by value, and copy (some) data from the input.  However,
//! there are also zero-copy versions of these traits, which are more
//! efficient (but not always applicable):
//!
//! - [`ParseBytesZC`]: Like [`ParseBytes`], but transmutes the byte string
//!   into an instance of the target type in place.
//!
//! - [`SplitBytesZC`]: Like [`SplitBytes`], but transmutes the byte string
//!   into an instance of the target type in place.
//!
//! - [`AsBytes`]: Allows interpreting an object as a byte string in place.
//!
//! # Primitive Types
//!
//! Wire-format support has been implemented for a number of built-in types.
//! Notably, [`u8`], slices, and arrays can be parsed into and built from.
//! These form the basic building blocks for every other wire-format type.
//!
//! After [`u8`], primitive integer types get somewhat more complicated.  To
//! facilitate zero-copy parsing, it should be possible to transmute an input
//! byte sequence into a wire-format type in place.  This is not possible with
//! Rust's built-in integer types, since they have alignment requirements and
//! use the platform's native endianness.  Instead, the custom types [`U16`],
//! [`U32`], and [`U64`] are provided; these can be used in the wire format.

mod build;
pub use build::{AsBytes, BuildBytes, TruncationError};

mod parse;
pub use parse::{
    ParseBytes, ParseBytesInPlace, ParseBytesZC, ParseError, SplitBytes,
    SplitBytesZC,
};

mod ints;
pub use ints::{U16, U32, U64};

mod size_prefixed;
pub use size_prefixed::SizePrefixed;
