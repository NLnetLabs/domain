#![cfg(all(
    feature = "unstable-zonetree",
    feature = "unstable-client-transport"
))]
#![cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "unstable-zonetree",
        feature = "unstable-client-transport"
    )))
)]
// #![warn(missing_docs)]
//! Experimental storing, querying and syncing a catalog of zones.

pub mod maintainer;
pub mod types;
