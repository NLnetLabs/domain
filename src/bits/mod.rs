//! Handling of DNS data.
//!
//! This module provides types and traits for working with DNS data. The types
//! allow creating such data from scratch and processing it. Crucially, the
//! module provides means to extract the data from wire-format DNS messages
//! and assemble such messages. Tools for processing the textual master format
//! representation of DNS data are not part of this module but can be found in
//! [master].
//!
//! [master]: ../master/index.html
//!
//!
//! # Representation of Variable-length Data and DNS Messages
//!
//! Various types have to deal with data of variable length. For instance, a
//! domain name can be anywhere between one and 255 bytes long. Such types,
//! all the way up to complete DNS messages, use the [`bytes::Bytes`] type
//! for holding the actual octets. Values of this type provide a good
//! compromise between the convenience of owned values and the performance
//! gained by using slices wherever possible. (The prize for the latter would
//! be excessive use of generic types and, worse yet, lifetime arguments all
//! over the place.)
//!
//! In order to distinguish between the various possible representations of
//! a sequence of bytes, the module attempts to use a consistent terminology.
//! The term ‘bytes’ will always mean a [`Bytes`] value; a `slice` or `byte
//! slice` is always a reference to a slice of `u8`; and a `vec` is always a
//! `Vec<u8>`. Thus a method `as_bytes` on a type would return a [`Bytes`]
//! reference of the types raw content, while `as_slice` will provide access
//! to the even more raw `[u8]` of it.
//!
//! [`bytes::Bytes`]: ../../bytes/struct.Bytes.html
//! [`Bytes`]: ../../bytes/struct.Bytes.html
//!
//!
//! # Parsing and Composing Messages
//!
//! In order to easily distinguish the process of creating and disecting
//! wire-format messages other forms of representation conversion such as
//! reading from a master file, we use the term *parsing* for extracting data
//! from a wire-format representation and *composing* for producing such a
//! representation. 
//!
//! Both parsing and composing happen on buffers holding a complete DNS
//! message. This seems to be a reasonably good choice given the limited 
//! size of DNS messages and the complexities introduced by to compress
//! domain names in message by referencing other parts of the message.
//! The details are explained in the [parse] and [compose] sub-modules.
//! Unless you are implementing your own resource record types, you are
//! unlikely to ever having to deal with parsing and composing directly.
//!
//! Instead, the types [`Message`] and [`MessageBuilder`] are there to make
//! parsing and constructing DNS messages easy. A [`Message`] takes the
//! binary data of a DNS message and allows iterating over its four
//! sections to look at the questions and resource records. Similarly,
//! a [`MessageBuilder`] takes a bytes vector (or creates one for you) and
//! has functionality to build the sections of the message step-by-step.//!
//!
//! [compose]: compose/index.html
//! [parse]: parse/index.html
//! [`Message`]: message/struct.Message.html
//! [`MessageBuilder`]: message_builder/struct.MessageBuilder.html
//!
//!
//! # Types for DNS Data
//!
//! The module contains a number of types for DNS data, both fundamental
//! and composed. Because they often come with a number of support types,
//! they are arranged in submodules. You will find detailed explanations for
//! all of them in their module. These are:
//!
//! * [charstr](charstr/index.html) for DNS character strings,
//! * [header](header/index.html) for the header of DNS messages,
//! * [name](name/index.html) for domain names,
//! * [opt](opt/index.html) for the record data of OPT records used in EDNS,
//! * [question](question/index.html) for questions,
//! * [serial](serial/index.html) for serial numbers of zones,
//! * [rdata](rdata/index.html) for infrastructure around record data; the
//!   actual implementations of the various record types are in the top-level
//!   [rdata](../rdata/index.html) module, and
//! * [record](record/index.html) for DNS resource records.
//!
//! The main types from each module are being reimported here.


//--- Re-exports

pub use self::charstr::{CharStr, CharStrMut};
pub use self::compose::{Compose, Compress, Compressor};
/*
pub use self::header::{Header, HeaderCounts, HeaderSection};
pub use self::message::{Message, MessageBuf};
pub use self::message_builder::{MessageBuilder, AnswerBuilder,
                                AuthorityBuilder, AdditionalBuilder};
pub use self::name::{DName, DNameBuf, DNameSlice, ParsedDName};
pub use self::parse::{Parser, ParseError, ParseResult};
pub use self::question::Question;
pub use self::rdata::{GenericRecordData, ParsedRecordData, RecordData};
pub use self::record::{GenericRecord, Record};
*/


//--- Modules

pub mod charstr;
pub mod compose;
    pub mod error;
    pub mod header;
    pub mod message;
    pub mod message_builder;
    pub mod name;
    pub mod opt;
    pub mod parse;
    pub mod question;
    pub mod serial;
    pub mod rdata;
    pub mod record;

