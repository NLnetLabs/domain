//! Domain names.
//!
//! This module provides various types for working with domain names.
//!
//! Main types: [`Dname`], [`RelativeDname`], [`ParsedDname`].<br/>
//! Main traits: [`ToDname`], [`ToRelativeDname`].
//! 
//! Domain names are a sequence of *labels.* For the most part, labels are
//! in turn a sequence of up to 63 octets. While they are limited to a
//! subset of ASCII by convention, all values are allowed. In their
//! wire-format representation labels are prefixed with an octet containing
//! the the number of octets in the label. The labels in a domain name are
//! nominally arranged backwards. That is, the ‘most significant’ label is
//! the last one. In an *absolute* domain name, this last label is an empty
//! label, called the *root label.* Only absolute names can appear inside
//! DNS messages.
//!
//! In order to save space in DNS messages (which were originally limited to
//! 512 bytes for most cases), a name can end in a pointer to another name
//! stored elsewhere in the message. This makes lazy message parsing somewhat
//! difficult since you need to carry around a reference to the original
//! message until actual parsing happens.
//!
//! As a consequence, this module provides three different basic types for
//! domain names: A self-contained, absolute domain name is represented by
//! [`Dname`], a self-contained, relative domain is [`RelativeDname`], and
//! a possibly compressed absolute domain name take from a message becomes
//! a [`ParsedDname`]. Each of these types internally contains a [`Bytes`]
//! value, which mean that it is an owned value that may refer to a shared
//! underlying byte slice and can be copied cheaply.
//!
//! All these types allow iterating over the labels of their domain names.
//! In addition, the self-contained types provide methods similar to 
//! [`Bytes`] that allow access to parts of the name.
//!
//! You can construct a new name either from a string containing the name in
//! the usual dots notation via the [`FromStr`] trait implemented by both
//! the self-contained types. To give you full control over building the name,
//! there is a [`DnameBuilder`] type that allows adding individual bytes or
//! entire labels to the name.
//!
//! However, because often you’ll need to add a suffix to a name,
//! for instance, to make it absolute, a way is provided to do that without
//! the need to copy or allocate. Instead, you can create a placeholder
//! value representing the chain of two names. This works via the
//! [`ToDname`] and [`ToRelativeDname`] traits which represent any type that
//! is an absolute or relative domain name. Functions and types accepting
//! domain names will generally be generic over these traits.
//!
//! [`Bytes`]: ../../../bytes/struct.Bytes.html
//! [`Dname`]: struct.Dname.html
//! [`DnameBuilder`]: struct.DnameBuilder.html
//! [`FromStr`]: ../../../std/str/trait.FromStr.html
//! [`ParsedDname`]: struct.ParsedDname.html
//! [`RelativeDname`]: struct.RelativeDname.html
//! [`ToDname`]: trait.ToDname.html
//! [`ToRelativeDname`]: trait.ToRelativeDname.html

pub use self::builder::DnameBuilder;
pub use self::chain::{Chain, ChainIter};
pub use self::dname::{Dname};
pub use self::error::{DnameError, FromStrError, IndexError, LabelTypeError,
                      LongLabelError, LongNameError, ParsedDnameError,
                      PushError, RelativeDnameError,
                      RootNameError, SplitLabelError, StripSuffixError};
pub use self::label::Label;
pub use self::parsed::{ParsedDname, ParsedDnameIter};
pub use self::relname::{RelativeDname, DnameIter};
pub use self::traits::{ToLabelIter, ToRelativeDname, ToDname};

mod builder;
mod chain;
mod dname;
mod error;
mod from_str;
mod label;
mod parsed;
mod relname;
mod traits;

