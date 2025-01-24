//! Domain names.
//!
//! Domain names are a core concept of DNS.  The whole system is essentially
//! just a mapping from domain names to arbitrary information.  This module
//! provides types and essential functionality for working with them.
//!
//! A domain name is a sequence of labels, separated by ASCII periods (`.`).
//! For example, `example.org.` contains three labels: `example`, `org`, and
//! `` (the root label).  Outside DNS-specific code, the root label (and its
//! separator) are almost always omitted, but keep them in mind here.
//!
//! Domain names form a hierarchy, where `b.a` is the "parent" of `.c.b.a`.
//! The owner of `example.org` is thus responsible for _every_ domain ending
//! with the `.example.org` suffix.  The reverse order in which this hierarchy
//! is expressed can sometimes be confusing.

mod label;
pub use label::{Label, LabelBuf, LabelIter};

mod absolute;
pub use absolute::Name;

mod reversed;
pub use reversed::{RevName, RevNameBuf};

mod unparsed;
pub use unparsed::UnparsedName;
