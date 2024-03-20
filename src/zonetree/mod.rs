#![cfg(feature = "zonefile")]
#![cfg_attr(docsrs, doc(cfg(feature = "zonefile")))]

pub use self::builder::{CnameError, ZoneBuilder, ZoneCutError};
pub use self::flavor::Flavor;
pub use self::read::{Answer, AnswerContent, ReadableZone};
pub(crate) use self::read::ReadZone;
pub use self::write::WriteableZone;
pub use self::rrset::{
    Rrset, SharedRr, SharedRrset, StoredDname, StoredRecord,
};
pub use self::set::{ZoneExists, ZoneSet};
pub use self::zone::{VersionMarker, Zone, ZoneData, ZoneVersions};
pub use self::versioned::Version;
pub use self::nodes::OutOfZone;

mod builder;
mod flavor;
mod nodes;
mod read;
mod rrset;
mod set;
mod versioned;
mod write;
mod zone;