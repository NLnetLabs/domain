//! Authenticated denial of existence mechanisms.
//!
//! In order for a DNSSEC server to deny the existence of a RRSET of the
//! requested type or name the server must have an RRSIG signature that it can
//! include in the response to authenticate it.
//!
//! However, an RRSIG signs an existing RRSET in a zone, it cannot sign a
//! non-existing RRSET. DNSSEC signers must therefore add records to the zone
//! that describe the record types and names that DO exist, which a server can
//! use to determine non-existence and which can signed providing an RRSIG to
//! authenticate the response.
//!
//! This module provides implementations of the zone signing related logic for
//! the NSEC ([RFC 4034]) and NSEC3 ([RFC 5155]) mechanisms which can be used
//! during DNSSEC zone signing to add this missing information to the zone
//! prior to signing.
//!
//! [RFC 4034]: https://www.rfc-editor.org/info/rfc4034
//! [RFC 5155]: https://www.rfc-editor.org/info/rfc5155
pub mod config;
pub mod nsec;
pub mod nsec3;
