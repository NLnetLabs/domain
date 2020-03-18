//! A DNS library for Rust – Core.
//!
//! This crate provides a number of modules related to the core functionality 
//! of the Domain Name System. Currently, these are:
//!
//! * fundamental types, traits, and implementations for dealing with DNS
//!   data,
//! * parsing of master file data (aka zonefiles) in the [master] module,
//! * data and master file access for various resource record types in the
//!   [rdata] module.
//!
//!
//! # Handling of DNS data.
//!
//! This module provides types and traits for working with DNS data. The types
//! allow creating such data from scratch and processing it. Crucially, the
//! module provides means to extract the data from wire-format DNS messages
//! and assemble such messages. Tools for processing the textual master format
//! representation of DNS data are not part of this module but can be found in
//! [master].
//!
//!
//! ## Representation of Variable-length Data and DNS Messages
//!
//! Various types have to deal with data of variable length. For instance, a
//! domain name can be anywhere between one and 255 bytes long. Since there
//! is no single best type to deal with such data – slices, vecs, or even
//! byte arrays may all be prefered in certain cases –, the crate uses a set
//! of traits to be able to be generic over bytes sequences. We call types
//! that provide these traits ‘octet sequences’ or simple ‘octets.’
//!
//! Different traits exist for octet references, owned octets, and octet
//! builder, that is types that allow constructing an octet stequence from
//! indidivual bytes or slice. The [octets] module contains all traits and
//! trait implementations. It also contains a detailed descriptions of the
//! traits, their purpose, and how it all fits together.
//!
//!
//! ## Parsing and Composing Messages
//!
//! In order to easily distinguish the process of creating and disecting
//! wire-format messages other forms of representation conversion such as
//! reading from a master file, we use the term *parsing* for extracting data
//! from a wire-format representation and *composing* for producing such a
//! representation. 
//!
//! Both parsing and composing happen on buffers holding a complete DNS
//! message. This seems to be a reasonable choice given the limited 
//! size of DNS messages and the complexities introduced by compressing
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
//! ## Types for DNS Data
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
//! * [serial](serial/index.html) for serial numbers of zones, and
//! * [record](record/index.html) for DNS resource records including record
//!   data. 
//!
//! [iana]: iana/index.html
//! [master]: master/index.html
//! [rdata]: rdata/index.html

#![no_std]

#[cfg(any(feature = "std"))]
#[allow(unused_imports)] // Import macros even if unused.
#[macro_use] extern crate std;

#[macro_use] extern crate core;

pub mod charstr;
pub mod cmp;
pub mod header;
pub mod iana;
pub mod master;
pub mod message;
pub mod message_builder;
pub mod name;
pub mod net;
pub mod octets;
pub mod opt;
pub mod rdata;
pub mod record;
pub mod question;
pub mod serial;
pub mod str;
pub mod utils;

