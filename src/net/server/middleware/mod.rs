//! Request pre-processing and response post-processing middleware.
//!
//! Middleware sits between the server and the application [`Service`],
//! pre-processing requests and post-processing responses in order to
//! filter/reject/modify them according to policy and standards.
//!
//! Middleware is implemented in terms of the [`Service`] trait, just like
//! your application service, but also takes a [`Service`] instance as an
//! argument. This is intended to enable middleware to be composed in layers
//! one atop another, each layer receiving and pre-processing requests from
//! the layer beneath, passing them on to the layer above and then
//! post-processing the resulting responses and propagating them back down
//! through the layers to the server.
//!
//! Currently the following middleware are available:
//!
//!   - [`MandatoryMiddlewareSvc`]: Core DNS RFC standards based message
//!         processing for MUST requirements.
//!   - [`EdnsMiddlewareSvc`]: RFC 6891 and related EDNS message processing.
//!   - [`CookiesMiddlewareSvc`]: RFC 7873 DNS Cookies related message
//!         processing.
//!
//! [`MandatoryMiddlewareSvc`]: mandatory::MandatoryMiddlewareSvc
//! [`EdnsMiddlewareSvc`]: edns::EdnsMiddlewareSvc
//! [`CookiesMiddlewareSvc`]: cookies::CookiesMiddlewareSvc
//! [`Service`]: crate::net::server::service::Service

#[cfg(feature = "siphasher")]
pub mod cookies;
pub mod edns;
pub mod mandatory;
pub mod notify;
pub mod stream;
pub mod tsig;
pub mod xfr;
