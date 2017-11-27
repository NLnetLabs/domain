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
pub mod rfc3596;

#[macro_use] mod macros;

use ::bits::name::Dname;

// The master_types! macro (defined in self::macros) creates the
// MasterRecordData enum produced when parsing master files (aka zone files).
// 
// Include all record types that can occur in master files. Place the name of
// the variant (identical to the type name) on the left side of the double
// arrow and the name of the type on the right.
//
// The macro creates the re-export of the record data type.
master_types!{
    rfc1035::{
        A => A,
        Cname => Cname<Dname>,
        Hinfo => Hinfo,
        Mb => Mb<Dname>,
        Md => Md<Dname>,
        Mf => Mf<Dname>,
        Mg => Mg<Dname>,
        Minfo => Minfo<Dname>,
        Mr => Mr<Dname>,
        Mx => Mx<Dname>,
        Ns => Ns<Dname>,
        Ptr => Ptr<Dname>,
        Soa => Soa<Dname>,
        Txt => Txt,
        Wks => Wks,
    }
    rfc2782::{
        Srv => Srv<Dname>,
    }
    rfc3596::{
        Aaaa => Aaaa,
    }
}

// The pseudo_types! macro (defined in self::macros) creates the re-exports
// for all the types not part of master_types! above.
pseudo_types!{
    rfc1035::{Null};
}

