//! DNS data.
//!
//! This module provides types for working with DNS data and parsing and
//! composing wire-format DNS messages.
//!
//! There are types for the most basic building blocks of DNS data, `DName`
//! for domain names, `CharStr` for character strings, and `Octets` for
//! arbitrary binary data. These types are cow-like, that is, they can
//! contain both borrowed or owned data. Using borrowed data avoids copying
//! when parsing messages, using owned data makes it easy to create these
//! types out of the blue, for instance when converting from zonefile data.
//! In addition, domain names know a third variant: packed. This variant
//! is created when parsing compressed domain names from a message. In order
//! to avoid allocations, compressed names are only unpacked when they are
//! actually needed. See the `name` module for more details.
//!
//! From those basic types, composite types are defined: `Question` for
//! the questions of a query, `Record` for resource records. The data of
//! resource records is defined in terms of a trait `RecordData` over which
//! records are generic. This module only defines the trait and a generic
//! type usable for all record types `GenericRecordData`. Types for concrete
//! record data are defined in the `domain::rdata` module instead.
//!
//! Both parsing and parsing happen on bytes buffers. While in theory they
//! could have been built on top of `Read` and `Write`, doing so on top of
//! buffers seemed more efficient or at least a hell of a lot more simple.
//! Luckily, unless you want to implement your own record data types, you
//! are unlikely to have to concern yourself with the details of either.
//!
//! Instead, the types `Message` and `MessageBuilder` are there to make
//! parsing and constructing DNS messages easy. A `Message` takes the
//! binary data of a DNS message and allows iterating over its four
//! sections to look at the questions and resource records. Similarly,
//! a `MessageBuilder` takes a bytes vector (or creates one for you) and
//! has functionality to step-by-step build the sections of the message.

pub use self::charstr::{CharStr, CharStrError};
pub use self::compose::{ComposeBytes, ComposeBuf};
pub use self::error::{ComposeError, ComposeResult, ParseError, ParseResult,
                      FromStrError, FromStrResult};
pub use self::iana::{Class, Opcode, Rcode, RRType};
pub use self::message::{Message, MessageBuf, MessageBuilder};
pub use self::name::{DName, DNameSlice, DNameBuf, PackedDName};
pub use self::nest::Nest;
pub use self::octets::Octets;
pub use self::parse::{ParseBytes};
pub use self::question::Question;
pub use self::rdata::{GenericRecordData, RecordData};
pub use self::record::Record;

pub mod charstr;
pub mod compose;
pub mod error;
pub mod header;
pub mod iana;
pub mod message;
pub mod name;
pub mod nest;
pub mod octets;
pub mod parse;
pub mod question;
pub mod rdata;
pub mod record;
mod u8;

