//! IANA Definitions for DNS.
//!
//! This module contains enums for parameters defined in IANA registries
//! that are relevant for this crate.
//!
//! All types defined hereunder follow the same basic structure. They are
//! all enums with all well-defined values as variants. In addition they
//! have an `Int` variant that contains a raw integer value. Since we cannot
//! restrict that integer to only the undefined values, we generally allow
//! the full set of possible values. We treat this correctly, meaning that
//! the well-defined variant and the `Int` variant with the same integer
//! value compare to equal.
//!
//! There are two methods `from_int()` and `to_int()` to convert from and
//! to raw integer values as well as implementations of the `From` trait
//! for these. `FromStr` and `Display` are implemented to convert from
//! the string codes to the values and back. All of these are essentially
//! giant matches which may or may not be the smartest way to do this.
//!
//! Types also implement `parse()` and `scan()` functions for creation from
//! wire format and representation format, respectively, as well as a
//! `compose()` method for composing into wire format data.
//!
//! While each parameter type has a module of its own, they are all
//! re-exported here. This is mostly so we can have associated types like
//! `FromStrError` without having to resort to devilishly long names.

pub use self::class::Class;
pub use self::digestalg::DigestAlgorithm;
pub use self::exterr::ExtendedErrorCode;
pub use self::nsec3::Nsec3HashAlgorithm;
pub use self::opcode::Opcode;
pub use self::opt::OptionCode;
pub use self::rcode::{OptRcode, Rcode, TsigRcode};
pub use self::rtype::Rtype;
pub use self::secalg::SecurityAlgorithm;
pub use self::sshfp::{SshfpAlgorithm, SshfpType};
pub use self::svcb::SvcParamKey;
pub use self::zonemd::{ZonemdAlgorithm, ZonemdScheme};

#[macro_use]
mod macros;

pub mod class;
pub mod digestalg;
pub mod exterr;
pub mod nsec3;
pub mod opcode;
pub mod opt;
pub mod rcode;
pub mod rtype;
pub mod secalg;
pub mod sshfp;
pub mod svcb;
pub mod zonemd;
