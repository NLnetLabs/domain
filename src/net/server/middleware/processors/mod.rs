//! Pre-supplied [`MiddlewareProcessor`] implementations.
//!
//! [`MiddlewareProcessor`]: super::processor::MiddlewareProcessor
#[cfg(feature = "siphasher")]
pub mod cookies;
pub mod mandatory;
