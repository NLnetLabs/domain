//! Tooling for interop testing.
extern crate bytes;
pub extern crate domain_core;
pub extern crate domain_resolv;
pub extern crate domain_tsig;

pub mod domain {
    pub use domain_core as core;
    pub use domain_resolv as resolv;
    pub use domain_tsig as tsig;
}

pub mod cargo;
pub mod nsd;
pub mod utils;

