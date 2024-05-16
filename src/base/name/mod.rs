//! Domain names.
//!
//! This module provides various types for working with domain names.
//!
//! Main types: [`Name`], [`RelativeName`], [`ParsedName`], [`UncertainName`],
//! [`NameBuilder`].<br/>
//! Main traits: [`ToName`], [`ToRelativeName`].
//!
//! Domain names are a hierarchical description of the location of records in
//! a tree. They are formed from a sequence of *labels* that describe the path
//! through the tree upward from the leaf node to the root.
//!
//! ## Domain name representations
//!
//! Domain names have multiple representations.
//!
//! The *wire format* representation is a binary encoding that is used when
//! including domain names in messages. In it, labels are just sequences of
//! octets prefixed by a length octet. The root of the tree is an empty label
//! and – because it always comes last when walking up the tree – implicitly
//! marks the end of the domain name. This label is often called the *root
//! label*. The entire name, including the root label, can be at most 255
//! octets long.
//!
//! This crate stores all domain names internally in this wire format. Thus,
//! all conversions from and to octets will always expect or provide octets
//! sequences containing domain names in wire format.
//!
//! The *presentation format* is a human readable representation of the domain
//! name. In it, the octets of each label are interpreted as ASCII characters
//! or, if there isn’t a printable one, as an escape sequence formed by a
//! backslash followed by the three-digit decimal value of the octet. Labels
//! are separated by dots. If a dot (or a backslash) appears as an octet in a
//! label, they can be escaped by preceding them with a backslash.
//!
//! This crate uses the presentation format when converting domain names from
//! and to strings.
//!
//! Finally, *internationalized domain names* (or IDN) is a way to encode
//! Unicode strings in labels using only ASCII characters. This encoding is
//! called _punicode._
//!
//! This crate currently does not support conversion from and to IDN
//! representations of domain names. This will be added in future versions.
//!
//!
//! ## Absolute, relative, and ‘uncertain’ domain names
//!
//! In some cases, it is useful to have a domain name that doesn’t end with
//! the root label. Such a name is called a *relative domain name* and,
//! conversely, a name that does end with the root label is called an *abolute
//! name*. Because these behave slightly differently, for instance, you can’t
//! include a relative name in a message, there are different types for those
//! two cases, [`Name`] for absolute names and [`RelativeName`] for relative
//! names.
//!
//! Sometimes, it isn’t quite clear if a domain name is absolute or relative.
//! This happens in presentation format where the final dot at the end
//! separating the empty and thus invisible root label is often omitted. For
//! instance, instead of the strictly correct `www.example.com.` the slightly
//! shorter `www.example.com` is accepted as an absolute name if it is clear
//! from context that the name is absolute. The [`UncertainName`] type
//! provides a means to keep such a name that may be absolute or relative.
//!
//! ## Name compression and parsed names.
//!
//! In order to save space in DNS messages (which were originally limited to
//! 512 bytes for most cases), a name can end in a pointer to another name
//! stored elsewhere in the message. This makes lazy message parsing somewhat
//! difficult since you need to carry around a reference to the original
//! message until actual parsing happens. The type [`ParsedDname`] takes care
//! of all that and will be returned when parsing a name from a message.
//!
//! ## Chained domain names and the name traits.
//!
//! When making a relative name absolute to be included in a message, you
//! often append a suffix to it. In order to avoid having to copy octets
//! around and make this cheap, the [`Chain`] type allows combining two other
//! name values. To make this work, the two traits [`ToName`] and
//! [`ToRelativeName`] allow writing code that is generic over any kind of
//! either absolute or relative domain name.
//!
//!
//! ## Building domain names
//!
//! You can create a domain name value from its presentation format using the
//! `FromStr` trait. Alternatively, the [`NameBuilder`] type allows you to
//! construct a name from scratch by appending octets, slices, or complete
//! labels.

pub use self::absolute::{Name, NameError};
pub use self::builder::{
    FromStrError, NameBuilder, PresentationError, PushError, PushNameError,
};
pub use self::chain::{Chain, ChainIter, LongChainError, UncertainChainIter};
pub use self::label::{
    Label, LabelTypeError, LongLabelError, OwnedLabel, SliceLabelsIter,
    SplitLabelError,
};
pub use self::parsed::{ParsedName, ParsedNameIter, ParsedSuffixIter};
pub use self::relative::{
    NameIter, RelativeFromStrError, RelativeName, RelativeNameError,
    StripSuffixError,
};
pub use self::traits::{FlattenInto, ToLabelIter, ToName, ToRelativeName};
pub use self::uncertain::UncertainName;

mod absolute;
mod builder;
mod chain;
mod label;
mod parsed;
mod relative;
mod traits;
mod uncertain;
