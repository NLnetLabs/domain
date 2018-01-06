//! Domain names.
//!
//! This module provides various types for working with domain names.
//!
//! Main types: [`Dname`], [`RelativeDname`], [`ParsedDname`],
//! [`UncertainDname`].<br/>
//! Main traits: [`ToDname`], [`ToRelativeDname`].
//! 
//! Domain names are a sequence of *labels* which are in turn a sequence of
//! up to 63 octets. While they are limited to a subset of ASCII by
//! convention, all values are allowed. In their wire-format representation
//! labels are prefixed with an octet containing the the number of octets in
//! the label. The labels in a domain name are nominally arranged backwards.
//! That is, the ‘most significant’ label is the last one. In an *absolute*
//! domain name, this last label is an empty label, called the *root label*
//! and indicating the root of the domain name tree. Only absolute names can
//! appear inside DNS messages.
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
//! a possibly compressed absolute domain name taken from a message becomes
//! a [`ParsedDname`]. Each of these types internally contains a [`Bytes`]
//! value, which means that it is an owned value that may refer to a shared
//! underlying byte slice and can be copied cheaply.
//!
//! All these types allow iterating over the labels of their domain names.
//! In addition, the self-contained types provide methods similar to 
//! [`Bytes`] that allow access to parts of the name.
//!
//! Sometimes, it isn’t quite clear if a domain name is absolute or relative.
//! This often happens because in a name’s string representation, which
//! contains each label’s content separated by dots, the final dot before the
//! empty root label is omitted. For instance, instead of the strictly
//! correct `www.example.com.` the slightly shorter `www.example.com` is
//! accepted as an absolute name if it is clear from context that the name
//! is absolute.
//!
//! TODO: Explain [`DnameBuilder`] and building from strings via
//!       [`UncertainDname`].
//!
//! [`Bytes`]: ../../../bytes/struct.Bytes.html
//! [`Dname`]: struct.Dname.html
//! [`DnameBuilder`]: struct.DnameBuilder.html
//! [`FromStr`]: ../../../std/str/trait.FromStr.html
//! [`ParsedDname`]: struct.ParsedDname.html
//! [`RelativeDname`]: struct.RelativeDname.html
//! [`ToDname`]: trait.ToDname.html
//! [`ToRelativeDname`]: trait.ToRelativeDname.html
//! [`UncertainDname`]: enum.UncertainDname.html

pub use self::builder::{DnameBuilder, PushError};
pub use self::chain::{Chain, ChainIter, LongChainError, UncertainChainIter};
pub use self::dname::{Dname, DnameError, DnameParseError, DnameBytesError};
pub use self::label::{Label, LabelTypeError, LongLabelError,
                      SplitLabelError};
pub use self::parsed::{ParsedDname, ParsedDnameIter, ParsedDnameError,
                       ParsedDnameAllError};
pub use self::relative::{RelativeDname, DnameIter, RelativeDnameError,
                         StripSuffixError};
pub use self::traits::{ToLabelIter, ToRelativeDname, ToDname};
pub use self::uncertain::{UncertainDname, FromStrError};

mod builder;
mod chain;
mod dname;
mod label;
mod parsed;
mod relative;
mod traits;
mod uncertain;

