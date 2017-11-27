//! Handling of DNS data.
//!
//! This module provides types and traits for working with DNS data as well
//! as parsing and composing wire-format DNS messages.
//!
//! # Working with DNS Data
//!
//! The module contains abstractions for two variable-length types used in
//! DNS: domain names and character strings. In both cases, the supplied types
//! are thin wrappers on top of a [`bytes::Bytes`] value. This means that
//! while they provide the convenience of owned types, copies are relatively
//! cheap.
//!
//! For character strings, there is only one type, [`CharStr`], while for
//! domain names, the situation is a little more diverse. For one, we strictly
//! distinguish between absolute and relative domain names. The basic two
//! types are [`Dname`] and [`RelativeDname`]. Because relative domain names
//! often have a suffix added, for instance to make them absolute, we provide
//! a means to combine several name into one logical name without copying the
//! underlying data via the [`RelativeDname::chain`] method. Finally,
//! wire-format DNS message may employ a concept called ‘name compression’
//! through which parts of a name may be spread all over the message. The type
//! [`ParsedDname`] allows to reference such a compressed name without the
//! need to reassemble it.
//!
//! Because there are so many different domain name types, two traits are
//! provided to build functions and composite types that are generic over any
//! name type. These two traits are [`ToDname`] and [`ToRelativeDname`] for
//! absolute and relative domain names respectively.
//!
//! In addition to these basic types, a number of composite types that appear
//! in DNS messaes are provided. The most important of these are [`Question`]
//! for the questions of a message, [`Record`] for resource records. 
//!
//! Instead of having one big enum, the data of resource records is kept
//! generic through the trait [`RecordData`]. The actual types implementing
//! these traits can by found in the crate’s [rdata] module.
//!
//! Further, there are three types for the header of a DNS message: [`Header`]
//! provides constants and flags whereas [`HeaderCounts`] contains the
//! element counts for the various sections, and [`HeaderSections`] is a
//! composite of the two.
//!
//! Finally, even though EDNS0 is mostly handled through the OPT record type
//! which would belong into the [rdata] module, it is important and
//! different enough to include it in the [bits::opt] module.
//!
//!
//! # Parsing and Composing Messages
//!
//! In order to easily distinguish the process of creating and disecting
//! wire-format messages from working with master files, we use the term
//! *parsing* and *composing* for reading from and writing to wire-format
//! data.
//!
//! Both parsing and composing happen on linear byte buffers. This seems
//! to be a reasonably good choice given the relatively small size of DNS
//! messages and the complexities introduced by name compression. The details
//! are explained in the [parse] and [compose] sub-modules. Unless you are
//! implementing your own resource record types, you are unlikely to ever
//! having to deal with parsing and composing directly.
//!
//! Instead, the types [`Message`] and [`MessageBuilder`] are there to make
//! parsing and constructing DNS messages easy. A [`Message`] takes the
//! binary data of a DNS message and allows iterating over its four
//! sections to look at the questions and resource records. Similarly,
//! a [`MessageBuilder`] takes a bytes vector (or creates one for you) and
//! has functionality to build the sections of the message step-by-step.
//!
//! [`bytes::Bytes`]: ../../bytes/struct.Bytes.html
//! [rdata]: ../rdata/index.html
//! [compose]: parse/compose.html
//! [bits::opt]: opt/index.html 
//! [parse]: parse/index.html
//! [`CharStr`]: charstr/struct.CharStr.html
//! [`Dname`]: name/struct.Dname.html
//! [`Header`]: header/struct.Header.html
//! [`HeaderCounts`]: header/struct.HeaderCounts.html
//! [`HeaderSection`]: header/struct.HeaderSection.html
//! [`Message`]: message/struct.Message.html
//! [`MessageBuilder`]: message_builder/struct.MessageBuilder.html
//! [`ParsedDname`]: name/struct.ParsedDname.html
//! [`Question`]: question/struct.Question.html
//! [`Record`]: record/struct.Record.html
//! [`RecordData`]: rdata/trait.RecordData.html
//! [`RelativeDname`]: name/struct.RelativeDname.html
//! [`RelativeDname::chain`]: name/struct.RelativeDname.html#method.chain
//! [`ToDname`]: name/trait.ToDname.html
//! [`ToRelativeDname`]: name/trait.ToRelativeDname.html


//--- Re-exports

/*
pub use self::charstr::{CharStr, CharStrBuf};
pub use self::compose::{Composable, Composer, ComposeError, ComposeMode,
                        ComposeResult, ComposeSnapshot};
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

