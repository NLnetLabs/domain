#![cfg(feature = "zonefile")]
#![cfg_attr(docsrs, doc(cfg(feature = "zonefile")))]

pub use self::builder::{CnameError, ZoneBuilder, ZoneCutError};
pub use self::flavor::Flavor;
pub use self::read::{Answer, AnswerContent, ReadZone};
pub use self::rrset::{
    Rrset, SharedRr, SharedRrset, StoredDname, StoredRecord,
};
pub use self::set::{ZoneExists, ZoneSet};
pub use self::zone::Zone;

mod builder;
mod flavor;
mod nodes;
mod read;
mod rrset;
mod set;
mod versioned;
mod zone;
