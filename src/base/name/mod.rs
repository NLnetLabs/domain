//! Domain names.
//!
//! This module provides various types for working with domain names.
//!
//! Main types: [`Dname`], [`RelativeDname`], [`ParsedDname`],
//! [`UncertainDname`], [`DnameBuilder`].<br/>
//! Main traits: [`ToDname`], [`ToRelativeDname`].
//!
//! Domain names are a sequence of *labels* which are in turn a sequence of
//! up to 63 octets. While they are limited to a subset of ASCII by
//! convention, all octet values are allowed. In their wire-format
//! representation labels are prefixed with an octet containing the the number
//! of octets in the label. The labels in a domain name are nominally arranged
//! backwards. That is, the ‘most significant’ label is the last one. In an
//! *absolute* domain name, this last label is an empty label, called the
//! *root label* and indicating the root of the domain name tree. Only
//! absolute names can appear inside DNS messages.
//!
//! In order to save space in DNS messages (which were originally limited to
//! 512 bytes for most cases), a name can end in a pointer to another name
//! stored elsewhere in the message. This makes lazy message parsing somewhat
//! difficult since you need to carry around a reference to the original
//! message until actual parsing happens.
//!
//! As a consequence, this module provides three different basic types for
//! domain names: A self-contained, absolute domain name is represented by
//! [`Dname`], a self-contained, relative domain is [`RelativeDname`]. These
//! are generic over an underlying octets sequence. Additionally, a possibly
//! compressed absolute domain name taken from a message becomes a
//! [`ParsedDname`]. This type is generic over an octets reference which makes
//! it a little more unwieldy.
//!
//! Sometimes, it isn’t quite clear if a domain name is absolute or relative.
//! This often happens because in a name’s string representation, which
//! contains each label’s content separated by dots, the final dot before the
//! empty root label is omitted. For instance, instead of the strictly
//! correct `www.example.com.` the slightly shorter `www.example.com` is
//! accepted as an absolute name if it is clear from context that the name
//! is absolute. The [`UncertainDname`] type provides a means to keep such
//! a name that may be absolute or relative.
//!
//! In order to make it cheap to combine names, a mechanism exists to chain
//! names together and treat them as a single name. The two traits [`ToDname`]
//! and [`ToRelativeDname`] allow writing code that is generic over any kind
//! of either absolute or relative domain name.
//!
//! Alternatively, you can use [`DnameBuilder`] to construct a name manually
//! from individual labels.
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

pub use self::builder::{
    DnameBuilder, FromStrError, PushError, PushNameError,
};
pub use self::chain::{Chain, ChainIter, LongChainError, UncertainChainIter};
pub use self::dname::{Dname, DnameError};
pub use self::label::{
    Label, LabelTypeError, LongLabelError, OwnedLabel, SliceLabelsIter,
    SplitLabelError,
};
pub use self::parsed::{ParsedDname, ParsedDnameIter, ParsedSuffixIter};
pub use self::relative::{
    DnameIter, RelativeDname, RelativeDnameError, RelativeFromStrError,
    StripSuffixError,
};
pub use self::traits::{ToDname, ToLabelIter, ToRelativeDname};
pub use self::uncertain::UncertainDname;

mod builder;
mod chain;
mod dname;
mod label;
mod parsed;
mod relative;
mod traits;
mod uncertain;
