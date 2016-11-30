//! Domain names.
//!
//! This module contains various types for working with domain names.
//! 
//! Domain names are a sequence of *labels.* For the most part, labels are
//! in turn a sequence of up to 63 octets. While they are limited to ASCII
//! by convention, all values are allowed. In their wire-format representation
//! labels are prefixed with an octet containing the the number of octets
//! in the label. The labels in a domain name are nominally arranged
//! backwards. That is, the ‘most significant’ label is the last one. In an
//! *absolute* domain name, this last label is an empty label, often called
//! the *root label.* Only absolute names can appear inside DNS messages.
//!
//! There are two twists to this: One are binary labels which essentially
//! encode a sequence of one-bit labels, are somewhat esoteric, and have been
//! declared historic. The other is name compression. In order to save
//! space in DNS messages (which were originally limited to 512 bytes for
//! most cases), a name can end in a pointer to another name stored
//! elsewhere in the message. This makes lazy message parsing somewhat
//! difficult since you need to carry around a reference to the original
//! message until actual parsing happens.
//!
//! This is why there are three types for domain names in this module. Two
//! types represent uncompressed domain names encoded in their wire format
//! atop a bytes sequence. The [`DNameSlice`] type is a slice of a domain
//! name akin to a `[u8]`. It is an unsized type and will have to be used
//! behind a pointer, typically a reference. The [`DNameBuf`] type acts as
//! its owned companion. Similar to the relationship between `[u8]` and a
//! `Vec<u8>` it derefs to a [`DNameSlice`] and provides facilities to
//! manipulate domain names. Both types can contain either absolute or
//! relative domain names.
//!
//! A compressed domain name can only occur in a parsed DNS message.
//! Accordingly, its type is called [`ParsedDName`]. It internally holds a
//! reference to the message it was parsed from. There’s only two things you
//! can do with a parsed domain name: convert it into a regular domain name
//! and iterate over its labels. Luckily, though, the latter is good enough
//! for comparing them to other domain names.
//!
//! Creating data structures that can use both [`DNameSlice`] and [`DNameBuf`]
//! can be achieved by being generic over `AsRef<DNameSlice>` as `AsRef` is
//! implemented both for `&DNameSlice` and `DNameBuf`. In order to allow
//! types that allow [`ParsedDName`] as well, there is an additional trait
//! [`DName`]. Naturally, the functionality provided by it is limited to
//! what [`ParsedDName`] can do: conversion into a regular domain name and
//! iteration over labels.
//!
//! # TODO
//!
//! - Implement an optimization where there is an optional first byte with
//!   the unallocated label type 0b10 that indicates whether the name is
//!   absolute or relative (ie., 0x80 means absolute and 0x81 relative and
//!   everything else means this really is the first byte of the domain
//!   name).
//!
//! [`DName`]: trait.DName.html
//! [`DNameSlice`]: struct.DNameSlice.html
//! [`DNameBuf`]: struct.DNameBuf.html
//! [`ParsedDName`]: struct.ParsedDName.html

pub use self::builder::{DNameBuilder, DNameBuildInto};
pub use self::dname::DName;
pub use self::iter::{NameLabels, NameLabelettes};
pub use self::label::{Label, LabelBuf, LabelContent, Labelette, LabelIter};
pub use self::parsed::ParsedDName;
pub use self::plain::{DNameBuf, DNameSlice, FromStrError, PushError};

mod builder;
mod dname;
mod from_str;
mod iter;
mod label;
mod parsed;
mod plain;

