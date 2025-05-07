//! Basic DNS.
//!
//! This module provides the essential types and functionality for working
//! with DNS.  In particular, it allows building and parsing DNS messages to
//! and from the wire format.
//!
//! This provides a mid-level and low-level API.  It guides users towards the
//! most efficient solutions for their needs, and (where necessary) provides
//! fallbacks that trade efficiency for flexibility and/or ergonomics.
//!
//! # A quick reference on types
//!
//! [`Message`] is the top-level type, representing a whole DNS message.  It
//! stores data in the wire format, making it trivial to parse into or build
//! from.  It can provide direct access to the message [`Header`], and the
//! questions and records within it (collectively called [`MessageItem`]s) can
//! be parsed/traversed using [`Message::parse()`].
//!
//! [`Question`] and [`Record`] are exactly what they look like, and are
//! simple `struct`s so they can be constructed and inspected easily.  They
//! are generic over a _domain name type_ (discussed below), which you will
//! need to pick explicitly.  [`Record`] is also generic over the record data
//! type; you probably want [`new_rdata::RecordData`].  See the documentation
//! on [`Record`] and [`new_rdata`] for more information.
//!
//! [`new_rdata`]: crate::new_rdata
//! [`new_rdata::RecordData`]: crate::new_rdata::RecordData
//!
//! The [`name`] module provides various types that represent domain
//! names, and describes the situations each type is most appropriate
//! for.  As a quick summary: try to use [`RevNameBuf`] by default, or
//! <code>Box&lt;[RevName]&gt;</code> if lots of domain names need to be
//! stored.  If DNSSEC canonical ordering is necessary, use [`NameBuf`] or
//! <code>Box&lt;[Name]&gt;</code> respectively.  There are more efficient
//! alternatives in some cases; see [`name`].
//!
//! [Name]: name::Name
//! [RevName]: name::RevName
//! [`NameBuf`]: name::NameBuf
//! [`RevNameBuf`]: name::RevNameBuf
//!
//! # Parsing DNS messages
//!
//! The [`parse`] module provides mid-level and low-level APIs for parsing
//! DNS messages from the wire format.  To parse the questions and records in
//! a [`Message`], use [`Message::parse()`].  To parse a message (including
//! questions and records) from bytes, use [`MessageParser::new()`].
//!
//! [`MessageParser::new()`]: parse::MessageParser::new()
//!
//! ```
//! # use domain::new_base::MessageItem;
//! # use domain::new_base::parse::MessageParser;
//! #
//! // The bytes to be parsed.
//! let bytes: &[u8] = &[
//!     // The message header.
//!     0, 42, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1,
//!     // A question: www.example.org. A IN
//!     3, b'w', b'w', b'w',
//!     7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
//!     3, b'o', b'r', b'g', 0,
//!     0, 1, 0, 1,
//!     // An answer: www.example.org. A IN 3600 127.0.0.1
//!     192, 12, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 127, 0, 0, 1,
//!     // An OPT record.
//!     0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 12,
//!       // An EDNS client cookie.
//!       0, 10, 0, 8, 6, 148, 57, 104, 176, 18, 234, 57,
//! ];
//!
//! // Construct a 'MessageParser' directly from bytes.
//! let Ok(mut message) = MessageParser::new(bytes) else {
//!     panic!("'bytes' was too small to be a valid 'Message'")
//! };
//! println!("Header: {:?}", message.header());
//! while let Some(item) = message.next() {
//!     let Ok(item) = item else {
//!         panic!("Could not parse a message item (at offset {})",
//!             message.offset());
//!     };
//!
//!     match item {
//!         MessageItem::Question(question) => {
//!             println!("Got a question: {question:?}");
//!         }
//!         MessageItem::Answer(answer) => {
//!             println!("Got an answer record: {answer:?}");
//!         }
//!         MessageItem::Authority(authority) => {
//!             println!("Got an authority record: {authority:?}");
//!         }
//!         MessageItem::Additional(additional) => {
//!             println!("Got an additional record: {additional:?}");
//!         }
//!         MessageItem::Edns(edns) => {
//!             println!("Got an EDNS record: {edns:?}");
//!         }
//!     }
//! }
//! ```
//!
//! # Building DNS messages
//!
//! The [`build`] module provides mid-level and low-level APIs for building
//! DNS messages in the wire format.  [`MessageBuilder`] is the primary entry
//! point; it writes into a user-provided byte buffer.
//!
//! [`MessageBuilder`]: build::MessageBuilder
//!
//! # Representing variable-length DNS data
//!
//! In order to efficiently serialize and deserialize DNS messages, and to be
//! easier to approach for users already familiar with DNS, this module
//! structures its DNS types to match the underlying wire format.
//!
//! Because many elements of DNS messages have variable-length encodings in
//! the wire format, this module relies on Rust's language support for
//! _dynamically sized types_ (DSTs) to represent them.  The top-level
//! [`Message`] type, [`CharStr`], [`Name`], etc. are all DSTs.
//!
//! [`Name`]: name::Name
//!
//! DSTs cannot be passed around by value because the compiler needs to know
//! (at compile-time) how much stack space to allocate for them.  As such, a
//! DST has to be held indirectly, by reference or in a container like
//! [`Box`].  The former work well in "short-term" contexts (e.g. within a
//! function), while the latter are necessary in long-term contexts.
//!
//! [`Box`]: https://doc.rust-lang.org/std/boxed/struct.Box.html
//!
//! Container types that implement [`UnsizedCopyFrom`] automatically work with
//! any [`UnsizedCopy`] types.  This trait allows DSTs to be copied into such
//! container types, which is especially useful to store a DST for long-term
//! use.  It is already implemented for [`Box`], [`Arc`], [`Vec`], etc., and
//! users can implement it on their own container types too.
//!
//! [`Arc`]: https://doc.rust-lang.org/std/sync/struct.Arc.html
//! [`Vec`]: https://doc.rust-lang.org/std/vec/struct.Vec.html
//! [`UnsizedCopy`]: crate::utils::dst::UnsizedCopy
//! [`UnsizedCopyFrom`]: crate::utils::dst::UnsizedCopyFrom

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

//--- DNS messages

mod message;
pub use message::{Header, HeaderFlags, Message, MessageItem, SectionCounts};

mod question;
pub use question::{QClass, QType, Question};

mod record;
pub use record::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RClass,
    RType, Record, UnparsedRecordData, TTL,
};

//--- Elements of DNS messages

pub mod name;

mod charstr;
pub use charstr::{CharStr, CharStrBuf, CharStrParseError};

mod serial;
pub use serial::Serial;

//--- Wire format

pub mod build;
pub mod parse;
pub mod wire;

//--- Compatibility exports

/// A compatibility module with [`domain::base`].
///
/// This re-exports a large part of the `new_base` API surface using the same
/// import paths as the old `base` module.  It is a stopgap measure to help
/// users port existing code over to `new_base`.  Every export comes with a
/// deprecation message to help users switch to the right tools.
pub mod compat {
    #![allow(deprecated)]
    #![allow(missing_docs)]

    #[deprecated = "use 'crate::new_base::HeaderFlags' instead."]
    pub use header::Flags;

    #[deprecated = "use 'crate::new_base::Header' instead."]
    pub use header::HeaderSection;

    #[deprecated = "use 'crate::new_base::SectionCounts' instead."]
    pub use header::HeaderCounts;

    #[deprecated = "use 'crate::new_base::RType' instead."]
    pub use iana::rtype::Rtype;

    #[deprecated = "use 'crate::new_base::name::Label' instead."]
    pub use name::Label;

    #[deprecated = "use 'crate::new_base::name::Name' instead."]
    pub use name::Name;

    #[deprecated = "use 'crate::new_base::Question' instead."]
    pub use question::Question;

    #[deprecated = "use 'crate::new_base::ParseRecordData' instead."]
    pub use rdata::ParseRecordData;

    #[deprecated = "use 'crate::new_rdata::UnknownRecordData' instead."]
    pub use rdata::UnknownRecordData;

    #[deprecated = "use 'crate::new_base::Record' instead."]
    pub use record::Record;

    #[deprecated = "use 'crate::new_base::TTL' instead."]
    pub use record::Ttl;

    #[deprecated = "use 'crate::new_base::Serial' instead."]
    pub use serial::Serial;

    pub mod header {
        #[deprecated = "use 'crate::new_base::HeaderFlags' instead."]
        pub use crate::new_base::HeaderFlags as Flags;

        #[deprecated = "use 'crate::new_base::Header' instead."]
        pub use crate::new_base::Header as HeaderSection;

        #[deprecated = "use 'crate::new_base::SectionCounts' instead."]
        pub use crate::new_base::SectionCounts as HeaderCounts;
    }

    pub mod iana {
        #[deprecated = "use 'crate::new_base::RClass' instead."]
        pub use class::Class;

        #[deprecated = "use 'crate::new_rdata::DigestType' instead."]
        pub use digestalg::DigestAlg;

        #[deprecated = "use 'crate::new_rdata::NSec3HashAlg' instead."]
        pub use nsec3::Nsec3HashAlg;

        #[deprecated = "use 'crate::new_edns::OptionCode' instead."]
        pub use opt::OptionCode;

        #[deprecated = "for now, just use 'u8', but a better API is coming."]
        pub use rcode::Rcode;

        #[deprecated = "use 'crate::new_base::RType' instead."]
        pub use rtype::Rtype;

        #[deprecated = "use 'crate::new_rdata::SecAlg' instead."]
        pub use secalg::SecAlg;

        pub mod class {
            #[deprecated = "use 'crate::new_base::RClass' instead."]
            pub use crate::new_base::RClass as Class;
        }

        pub mod digestalg {
            #[deprecated = "use 'crate::new_rdata::DigestType' instead."]
            pub use crate::new_rdata::DigestType as DigestAlg;
        }

        pub mod nsec3 {
            #[deprecated = "use 'crate::new_rdata::NSec3HashAlg' instead."]
            pub use crate::new_rdata::NSec3HashAlg as Nsec3HashAlg;
        }

        pub mod opt {
            #[deprecated = "use 'crate::new_edns::OptionCode' instead."]
            pub use crate::new_edns::OptionCode;
        }

        pub mod rcode {
            #[deprecated = "for now, just use 'u8', but a better API is coming."]
            pub use u8 as Rcode;
        }

        pub mod rtype {
            #[deprecated = "use 'crate::new_base::RType' instead."]
            pub use crate::new_base::RType as Rtype;
        }

        pub mod secalg {
            #[deprecated = "use 'crate::new_rdata::SecAlg' instead."]
            pub use crate::new_rdata::SecAlg;
        }
    }

    pub mod name {
        #[deprecated = "use 'crate::new_base::name::Label' instead."]
        pub use crate::new_base::name::Label;

        #[deprecated = "use 'crate::new_base::name::Name' instead."]
        pub use crate::new_base::name::Name;
    }

    pub mod question {
        #[deprecated = "use 'crate::new_base::Question' instead."]
        pub use crate::new_base::Question;
    }

    pub mod rdata {
        #[deprecated = "use 'crate::new_base::ParseRecordData' instead."]
        pub use crate::new_base::ParseRecordData;

        #[deprecated = "use 'crate::new_rdata::UnknownRecordData' instead."]
        pub use crate::new_rdata::UnknownRecordData;
    }

    pub mod record {
        #[deprecated = "use 'crate::new_base::Record' instead."]
        pub use crate::new_base::Record;

        #[deprecated = "use 'crate::new_base::TTL' instead."]
        pub use crate::new_base::TTL as Ttl;
    }

    pub mod serial {
        #[deprecated = "use 'crate::new_base::Serial' instead."]
        pub use crate::new_base::Serial;
    }
}
