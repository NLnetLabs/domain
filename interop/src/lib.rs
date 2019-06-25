//! Tooling for interop testing.

pub mod domain {
    pub use domain_core as core;
    pub use domain_resolv as resolv;
    pub use domain_tsig as tsig;
}

pub mod cargo;
pub mod nsd;
pub mod utils;

