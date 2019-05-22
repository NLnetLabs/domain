//! Resource data implementations.
//!
//! This module will eventually contain implementations for the record data
//! for all defined resource record types.
//!
//! The types are named identically to the [`Rtype`] variant they implement.
//! They are grouped into submodules for the RFCs they are defined in. All
//! types are also re-exported at the top level here. Ie., for the AAAA
//! record type, you can simple `use domain::rdata::Aaaa` instead of
//! `use domain::rdata::rfc3596::Aaaa` which nobody could possibly remember.
//! There are, however, some helper data types defined here and there which
//! are not re-exported to keep things somewhat tidy.
//!
//! See the [`Rtype`] enum for the complete set of record types and,
//! consequently, those types that are still missing.
//!
//! [`Rtype`]: ../iana/enum.Rtype.html

pub mod rfc1035;
pub mod rfc2782;
pub mod rfc2845;
pub mod rfc3596;
pub mod rfc4034;
pub mod rfc5155;
pub mod rfc7344;

#[macro_use]
mod macros;
use crate::bits::opt::Opt;

// The rdata_types! macro (defined in self::macros) reexports the record data
// types here and creates the MasterRecordData and AllRecordData enums
// containing all record types that can appear in master files or all record
// types that exist.
//
// All record data types listed here should have the same name as the
// `Rtype` variant they implement.
//
// Add any new module here and then add all record types in that module that
// can appear in master files under "master" and all others under "pseudo".
// In both cases, if your type is generic over a domain name type, add `<N>`
// to it (it can’t be over anything else, so if you have more type arguments,
// you might have to either newtype with those removes or, God forbid, modify
// the macro). Each type entry has to be followed by a comma, even the last
// one.
rdata_types! {
    rfc1035::{
        master {
            A,
            Cname<N>,
            Hinfo,
            Mb<N>,
            Md<N>,
            Mf<N>,
            Minfo<N>,
            Mr<N>,
            Mx<N>,
            Ns<N>,
            Ptr<N>,
            Soa<N>,
            Txt,
            Wks,
        }
        pseudo {
            Null,
        }
    }
    rfc2782::{
        master {
            Srv<N>,
        }
    }
    rfc2845::{
        pseudo {
            Tsig<N>,
        }
    }
    rfc3596::{
        master {
            Aaaa,
        }
    }
    rfc4034::{
        master {
            Dnskey,
            Rrsig,
            Nsec<N>,
            Ds,
        }
    }
    rfc5155::{
        master {
            Nsec3,
            Nsec3param,
        }
    }
    rfc7344::{
        master {
            Cdnskey,
            Cds,
        }
    }
}

pub mod parsed {
    pub use super::rfc1035::parsed::*;
    pub use super::rfc2782::parsed::*;
    pub use super::rfc3596::parsed::*;
    pub use super::rfc4034::parsed::*;
    pub use super::rfc5155::parsed::*;
    pub use super::rfc7344::parsed::*;
}
