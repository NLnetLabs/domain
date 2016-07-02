//! IANA Definitions for DNS.
//!
//! See http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
//! and http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
//! for the canonical source of these definitions.
//!
//! This module represents the state of the source as per 2016-03-10.
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

pub use self::class::Class;
pub use self::opcode::Opcode;
pub use self::opt::OptionCode;
pub use self::rcode::Rcode;
pub use self::rrtype::RRType;
pub use self::secalg::SecAlg;

mod class;
mod opcode;
mod opt;
mod rcode;
mod rrtype;
mod secalg;

