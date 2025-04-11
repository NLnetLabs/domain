//! Basic DNS.
//!
//! This module provides the essential types and functionality for working
//! with DNS.  Crucially, it provides functionality for parsing and building
//! DNS messages on the wire.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

//--- DNS messages

mod message;
pub use message::{Header, HeaderFlags, Message, SectionCounts};

mod question;
pub use question::{QClass, QType, Question, UnparsedQuestion};

mod record;
pub use record::{
    CanonicalRecordData, ParseRecordData, RClass, RType, Record,
    UnparsedRecordData, TTL,
};

//--- Elements of DNS messages

pub mod name;

mod charstr;
pub use charstr::CharStr;

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
