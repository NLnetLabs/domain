// TODO:
//
//    o  Rename ShortParser into something more generic.
//
//! DNS data.
//!
//! This module provides types and traits for working with DNS data as well
//! as parsing and composing wire-format DNS messages.
//!
//! # Working with DNS Data
//!
//! The module contains abstractions for two concepts used in DNS data:
//! domain names and character strings. In both cases, the supplied types
//! internally contain the binary data and work directly on it. Similar 
//! to raw bytes slices, there types for borrowed and owned domain names
//! and character strings where the owned type derefs to the borrowed one.
//! For domain names, these types are [`DNameSlice`] and [`DNameBuf`];
//! for character strings [`CharStr`] and [`CharStrBuf`].
//!
//! For domain names there is a third variant, [`ParsedDName`]. This type is
//! necessary to represent compressed names where the remainder of a name is
//! to be found elsewhere in the message. It avoids allocations when access
//! to the entire name isn’t necessary.
//!
//! Traits are used when constructing composite types to allow them to work
//! on borrowed and owned data as well as on parsed domain names. For
//! character strings and raw bytes data, `AsRef<CharStr>` and `AsRef<[u8]>`
//! are being used. For domain names, there is a separate trait, [`DName`]
//! with the same purpose. However, its functionality is limited to the
//! what parsed domain names can provide.
//!
//! A number of composite types are already defined: [`Question`] for
//! the questions of a query, [`Record`] for resource records. 
//!
//! Instead of having one big enum, the data of resource records is kept
//! generic through two traits: [`RecordData`] provides functions common to
//! all variants of record data types while [`ParsedRecordData`] adds
//! the ability to construct a value from a wire-format message for those
//! variants that can use borrowed data and parsed domain names. The actual
//! types implementing these traits can by found in the crate’s [rdata]
//! module.
//!
//! # Parsing and Composing Messages
//!
//! In order to easily distinguish the process of creating and disecting
//! wire-format messages from working with master files, we use the term
//! *parsing* and *composing* for reading from and writing to wire-format
//! data.
//!
//! Both parsing and composing happen on bytes buffers. This seems to be a
//! reasonably good choice given the relatively small size of DNS messages and
//! the complexities introduced by name compression. The details are
//! explained in the [parse] and [compose] sub-modules. Unless you are
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
//! [rdata]: ../rdata/index.html
//! [compose]: compose/index.html
//! [parse]: parse/index.html
//! [`CharStr`]: charstr/struct.CharStr.html
//! [`CharStrBuf`]: charstr/struct.CharStrBuf.html
//! [`DName`]: name/trait.DName.html
//! [`DNameBuf`]: name/struct.DNameBuf.html
//! [`DNameSlice`]: name/struct.DNameSlice.html
//! [`Message`]: message/struct.Message.html
//! [`MessageBuilder`]: message_builder/struct.MessageBuilder.html
//! [`ParsedDName`]: name/struct.ParsedDName.html
//! [`ParsedRecordData`]: rdata/trait.ParsedRecordData.html
//! [`Question`]: question/struct.Question.html
//! [`Record`]: record/struct.Record.html
//! [`RecordData`]: rdata/trait.RecordData.html


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
pub mod name;
pub mod opt;
pub mod parse;
pub mod question;
pub mod rdata;
pub mod record;

/*
pub mod message_builder;
*/
