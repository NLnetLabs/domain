//! IANA Definitions for DNS.
//!
//! See http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
//! for the canonical source of these definitions.
//!
//! This module represents the state of the source as per 2016-03-10.

pub use self::class::Class;
pub use self::opcode::Opcode;
pub use self::rcode::Rcode;
pub use self::rrtype::RRType;

pub mod class;
pub mod opcode;
pub mod rcode;
pub mod rrtype;

