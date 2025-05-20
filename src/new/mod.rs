//! A new API for `domain`.
//!
//! This module mirrors the top-level layout of `domain`, except that the
//! sub-modules it provides have brand new APIs.  These are designed from
//! scratch and take advantage of new advances (e.g. in the Rust language
//! itself) to provide more ergonomic and efficient interfaces of the same
//! functionality.
//!
//! ## About the Domain Name System
//!
//! In one sentence: DNS is a hierarchial mapping of human-readable _domain
//! names_ to arbitrary information.  Its most important function has been
//! (and continues to be) to resolve a human-readable name for a server into
//! an IP address: this is the basis for the World Wide Web.  Its importance
//! to the Internet as a whole has led to massive amounts of development
//! effort and infrastructure surrounding it.
//!
//! There are two basic parts to DNS: the information stored in DNS, how it is
//! structured, and its management; and the DNS protocol, which is used for
//! communicating that information.  The two are naturally linked, but the
//! former is more abstract and the latter is quite practical.  Both are
//! standardized by a large number of Internet Standards, the most well-known
//! of which may be [RFC 1034] and [RFC 1035].
//!
//! [RFC 1034]: https://datatracker.ietf.org/doc/html/rfc1034
//! [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
//!
//! ## The `domain` Crate
//!
//! `domain` is a library for operating on and with the Domain Name System.
//! It provides a versatile toolbox for building new DNS software, whether
//! that is a simple embedded DNS client or a high-performance DNS server.
//! Its layered API provides dedicated, high-level interfaces for common
//! tasks, and gracefully falls back to more flexible and powerful interfaces
//! when those are not enough.
//!
//! DNS is a vast and complex system in practice, due to ambiguity in the
//! relevant standards, variation in implementation-defined behaviour, the
//! free-form nature of the information stored, and the need for reliability
//! in the face of it all.  `domain`'s goal is to help users get DNS right.
//! Its APIs do the right thing by default, while providing the necessary
//! fallbacks when users have complex requirements and need manual control.
//!
//! The following sections describe some of the use cases for DNS, and the
//! facilities provided by `domain` for them.
//!
// TODO:
// - "Retrieving information via DNS"
// - "Serving information over DNS"
// - "Cryptographic security for DNS"
//
//! ## Doing DNS Manually
//!
//! When especially irregular operations are required, or custom high-level
//! interfaces need to be built, `domain`'s low-level APIs are useful.  The
//! primary entry point for this is the [`base`] module.  It defines core DNS
//! data types and implements building to and parsing from the wire format.
//!
//! Alongside [`base`], [`rdata`] defines the standard DNS record data types,
//! like [`rdata::A`] and [`rdata::Ns`].  It also provides containers which
//! can hold any known or unknown record data type.  Together, these modules
//! provide the basic essence of DNS that any operation can be built around.

pub mod base;
pub mod edns;
pub mod rdata;
