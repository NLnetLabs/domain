//! Pre-supplied [`MiddlewareProcessor`] implementations.
//!
//! [`MiddlewareProcessor`]: super::processor::MiddlewareProcessor

#[cfg(feature = "siphasher")]
pub mod cookies;
#[cfg(feature = "siphasher")]
pub mod cookies_svc;
pub mod edns;
pub mod edns_svc;
pub mod mandatory;
pub mod mandatory_svc;