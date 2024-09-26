//! RFC 5936 AXFR and RFC 1995 IXFR request handling middleware.
//!
//! This module provides the [`XfrMiddlewareSvc`] service which responds to
//! [RFC 5936] AXFR and [RFC 1995] IXFR requests to perform entire or
//! incremental difference based zone transfers.
//!
//! Determining which requests to honour and with what data is delegated to a
//! caller supplied implementation of the [`XfrDataProvider`] trait.
//! [`XfrDataProvider`] implementations for [`Zone`] and [`ZoneTree`] are
//! provided allowing those types to be used as-is as XFR data providers with
//! this middleware service.
//!
//! # Requiring TSIG authenticated XFR requests
//!
//! To require XFR requests to be TSIG authenticated, implement
//! `XfrDataProvider<Option<Key>>`, extract the key data using
//! [`Request::metadata()`] and verify that a TSIG key was used to sign the
//! request, and that the name and algorithm of the used key are acceptable to
//! you.
//!
//! You can then use your [`XfrDataProvider`] impl with [`XfrMiddlewareSvc`],
//! and add [`TsigMiddlewareSvc`] directly before [`XfrMiddlewareSvc`] in the
//! middleware layer stack so that the used `Key` is made available from the
//! TSIG middleware to the XFR middleware.
//!
//! # Limitations
//!
//! * RFC 1995 2 Brief Description of the Protocol states: _"To ensure
//!   integrity, servers should use UDP checksums for all UDP responses."_.
//!   This is not implemented.
//!
//! [RFC 5936]: https://www.rfc-editor.org/info/rfc5936
//! [RFC 1995]: https://www.rfc-editor.org/info/rfc1995
//! [`Request::metadata()`]: crate::net::server::message::Request::metadata
//! [`TsigMiddlewareSvc`]:
//!     crate::net::server::middleware::tsig::TsigMiddlewareSvc
//! [`XfrDataProvider`]: super::data_provider::XfrDataProvider
//! [`Zone`]: crate::net::zonetree::Zone
//! [`ZoneTree`]: crate::net::zonetree::ZoneTree
mod axfr;
mod batcher;
mod ixfr;
mod responder;
mod util;

pub mod data_provider;
pub mod service;

pub use data_provider::{XfrData, XfrDataProvider, XfrDataProviderError};
pub use service::XfrMiddlewareSvc;

#[cfg(test)]
mod tests;
