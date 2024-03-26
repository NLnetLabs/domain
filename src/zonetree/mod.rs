//! Building, querying and iterating over zone trees.
//!
//!
#![cfg(feature = "unstable-zonetree")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-zonetree")))]

mod tree;
mod types;
mod walk;
mod zone;

pub mod answer;
pub mod in_memory;
pub mod traits;

pub use self::answer::Answer;
pub use self::traits::{
    ReadableZone, WriteableZone, WriteableZoneNode, ZoneStore,
};
pub use self::tree::{ZoneExists, ZoneTree};
pub use self::types::{
    Rrset, SharedRr, SharedRrset, StoredDname, StoredRecord,
};
pub use self::walk::WalkOp;
pub use self::zone::Zone;
