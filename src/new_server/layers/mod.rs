//! Common plug-in functionality for DNS servers.

pub mod cookie;
pub use cookie::CookieLayer;

mod min_any;
pub use min_any::MinAnyLayer;
