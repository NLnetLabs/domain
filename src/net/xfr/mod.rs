#![cfg_attr(
    not(feature = "unstable-xfr"),
    doc = " The `unstable-xfr` feature is necessary to enable this module."
)]
#![cfg(feature = "unstable-xfr")]
// #![warn(missing_docs)]
// #![warn(clippy::missing_docs_in_private_items)]
//! XFR related functionality.
//!
//! # What is XFR?
//!
//! XFR refers to the protocols used to transfer entire zones between
//! nameservers.
//!
//! There are two XFR protocols and a couple of protocols often used in
//! combination with XFR:
//!
//! - AXFR defined by [RFC 5936] "DNS Zone Transfer Protocol (AXFR)"
//! - IXFR defined by [RFC 1995] "Incremental Zone Transfer in DNS"
//! - NOTIFY defined by [RFC 1996] "A Mechanism for Prompt Notification of
//!   Zone Changes"
//! - TSIG defined by [RFC 8945] "Secret Key Transaction Authentication for
//!   DNS (TSIG)"
//!
//! AXFR is used to transfer a complete zone via one or more DNS responses.
//!
//! IXFR is used to incrementally apply the changes that occur to a zone on
//! one nameserver to the same zone on another server, assuming that the
//! latter server has a reasonably up-to-date copy of the zone.
//!
//! NOTIFY allows the server that holds the primary copy of a zone to notify
//! interested servers that the zone has changed and should be re-fetched.
//!
//! TSIG can be used to sign XFR requests and responses to authenticate the
//! servers involved to each other.
//!
//! # XFR support available in this crate
//!
//! Sending requests & handling responses:
//! - [`net::client::stream`] supports sending of XFR requests and receiving
//!   one or more responses via [`RequestMessage`].
//! - [`net::client::tsig`] can be wrapped around another transport to add
//!   TSIG request signing and response validation.
//! - [`net::xfr::protocol::XfrResponseInterpreter`] can be used to parse
//!   those XFR responses into [`ZoneUpdate`]s.
//! - [`zonetree::update::ZoneUpdater`] can then be used to apply those
//!   updates to a [`Zone`].
//!
//! Responding to requests:
//! - [`net::server::middleware::xfr::XfrMiddlewareSvc`] can respond to
//!   XFR requests with zone transfer responses.
//! - [`net::server::middleware::tsig::TsigMiddlewareSvc`] can validate
//!   request signatures and sign transer responses.
//! - [`net::server::middleware::notify::NotifyMiddlewareSvc`] can invoke
//!   a user supplied callback when a NOTIFY request is received.
//!
//! [RFC 5936]: https://www.rfc-editor.org/info/rfc5936
//! [RFC 1995]: https://www.rfc-editor.org/info/rfc1995
//! [RFC 1996]: https://www.rfc-editor.org/info/rfc1996
//! [RFC 8945]: https://www.rfc-editor.org/info/rfc8945
//! [`net::client::stream`]: crate::net::client::stream
//! [`RequestMessage`]: crate::net::client::request::RequestMessage
//! [`net::client::tsig`]: crate::net::client::tsig
//! [`net::xfr::protocol::XfrResponseInterpreter`]: crate::net::xfr::protocol::XfrResponseInterpreter
//! [`ZoneUpdate`]: crate::zonetree::types::ZoneUpdate
//! [`zonetree::update::ZoneUpdater`]: crate::zonetree::update::ZoneUpdater
//! [`Zone`]: crate::zonetree::Zone
//! [`net::server::middleware::xfr::XfrMiddlewareSvc`]: crate::net::server::middleware::xfr::XfrMiddlewareSvc
//! [`net::server::middleware::tsig::TsigMiddlewareSvc`]: crate::net::server::middleware::tsig::TsigMiddlewareSvc
//! [`net::server::middleware::notify::NotifyMiddlewareSvc`]: crate::net::server::middleware::notify::NotifyMiddlewareSvc

pub mod protocol;
