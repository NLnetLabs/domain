//! Pre-supplied [`MiddlewareProcessor`] implementations.
//!
//! [`MiddlewareProcessor`]: middleware::processor::MiddlewareProcessor
#[cfg(feature = "siphasher")]
pub mod cookies;
pub mod mandatory;
