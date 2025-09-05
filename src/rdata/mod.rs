//! Record Data of Well-defined Record Types
//!
//! This module will eventually contain implementations for the record data
//! of all defined resource record types.
//!
//! The types are named identically to the
//! [`domain::base::iana::Rtype`][crate::base::iana::Rtype] variant they
//! implement. They are grouped into submodules for the RFCs they are defined
//! in. All types are also re-exported at the top level here. Ie., for the
//! AAAA record type, you can simply `use domain::rdata::Aaaa` instead of
//! `use domain::rdata::rfc3596::Aaaa` which nobody could possibly
//! remember. There are, however, some helper data types defined here and
//! there which are not re-exported to keep things somewhat tidy.
//!
//! See the [`domain::base::iana::Rtype`][crate::base::iana::Rtype] enum for
//! the complete set of record types and, consequently, those types that are
//! still missing.
//!
//! In addition, the module provides two enums combining the known types.
//! [`AllRecordData`] indeed contains all record data types known plus
//! [`UnknownRecordData`] for the rest, while [`ZoneRecordData`] only
//! contains those types that can appear in zone files plus, again,
//! [`UnknownRecordData`] for everything else.

// A note on implementing record types with embedded domain names with regards
// to compression and canonical representation:
//
// RFC 3597 stipulates that only record data of record types defined in RFC
// 1035 is allowed to be compressed. (These are called “well-known record
// types.”) For all other types, `CompressDname::append_compressed_name`
// must not be used and the names be composed with `ToDname::compose`.
//
// RFC 4034 defines the canonical form of record data. For this form, domain
// names included in the record data of the following record types must be
// composed canonically using `ToName::compose_canonical`: All record types
// from RFC 1035 plus RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6,
// RRSIG, NSEC. All other record types must be composed canonically using
// `ToName::compose`.
//
// The macros module contains three macros for generating name-only record
// types in these three categories: `name_type_well_known!` for types from
// RFC 1035, `name_type_canonical!` for non-RFC 1035 types that need to be
// lowercased, and `name_type!` for everything else.

#[macro_use]
mod macros;

pub mod aaaa;
pub mod cds;
pub mod dname;
pub mod dnssec;
pub mod naptr;
pub mod nsec3;
pub mod openpgpkey;
pub mod rfc1035;
pub mod srv;
pub mod sshfp;
pub mod svcb;
pub mod tlsa;
pub mod tsig;
pub mod zonemd;

// The rdata_types! macro (defined in self::macros) defines the modules
// containing the record data types, re-exports those here, and creates the
// ZoneRecordData and AllRecordData enums containing all record types that
// can appear in a zone file and all record types that exist.
//
// All record data types listed here MUST have the same name as the
// `Rtype` variant they implement – some of the code implemented by the macro
// relies on that.
//
// Add any new module here and then add all record types in that module that
// can appear in zone files under "zone" and all others under "pseudo".
// Your type can be generic over an octet type "O" and a domain name type "N".
// Add these as needed. Trait bounds on them differ for different methods, so
// check the bounds on ZoneRecordData and AllRecordData if there are errors.
rdata_types! {
    rfc1035::{
        zone {
            A,
            Cname<N>,
            Hinfo<O>,
            Mb<N>,
            Md<N>,
            Mf<N>,
            Mg<N>,
            Minfo<N>,
            Mr<N>,
            Mx<N>,
            Ns<N>,
            Ptr<N>,
            Soa<N>,
            Txt<O>,
        }
        pseudo {
            Null<O>
        }
    }
    aaaa::{
        zone {
            Aaaa,
        }
    }
    cds::{
        zone {
            Cdnskey<O>,
            Cds<O>,
        }
    }
    dname::{
        zone {
            Dname<N>,
        }
    }
    dnssec::{
        zone {
            Dnskey<O>,
            Rrsig<O, N>,
            Nsec<O, N>,
            Ds<O>,
        }
    }
    naptr::{
        zone {
            Naptr<O, N>,
        }
    }
    nsec3::{
        zone {
            Nsec3<O>,
            Nsec3param<O>,
        }
    }
    openpgpkey::{
        zone {
            Openpgpkey<O>,
        }
    }
    srv::{
        zone {
            Srv<N>,
        }
    }
    sshfp::{
        zone {
            Sshfp<O>,
        }
    }
    svcb::{
        pseudo {
            Svcb<O, N>,
            Https<O, N>,
        }
    }
    tlsa::{
        zone {
            Tlsa<O>,
        }
    }
    tsig::{
        pseudo {
            Tsig<O, N>,
        }
    }
    zonemd::{
        zone {
            Zonemd<O>,
        }
    }
}
