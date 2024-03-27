#![cfg(feature = "unstable-zonetree")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-zonetree")))]
#![warn(missing_docs)]
//! Storing and querying of zone trees.
//!
//! A [`ZoneTree`] is a multi-rooted hierarchy of [`Zone`]s, each root being a
//! distinct [`Class`]. A tree can be queried by [`Class`], [`Rtype`] and
//! [`Dname`] resulting in an [`Answer`].
//!
//! Trees can be iterated over to inspect or export their content.
//!
//! In-memory [`Zone`]s can be created from DNS records using [`ZoneBuilder`],
//! inserted into a [`ZoneTree`], looked up in the tree (by exact or closest
//! matching name) and removed from the tree.
//!
//! Zones with other types of backing store can be created by implementing the
//! [`ZoneStore`] trait and passing an instance of the implementing struct to
//! [`Zone::new()`].
//!
//! For an example of implementing an alternate zone backing store see
//! `examples/other/mysql-zone.rs`.
//!
//! # Usage
//!
//! The following example builds and queries a [`ZoneTree`] containing a single
//! in-memory [`Zone`].
//!
//! ```
//! use domain::base::iana::{Class, Rcode, Rtype};
//! use domain::base::name::Dname;
//! use domain::zonefile::{inplace, parsed};
//! use domain::zonetree::ZoneBuilder;
//! use domain::zonetree::{Answer, Zone, ZoneTree};
//!
//! // Prepare some zone file bytes to demonstrate with.
//! let zone_file = include_bytes!("../../test-data/zonefiles/nsd-example.txt");
//! let mut zone_bytes = std::io::BufReader::new(&zone_file[..]);
//!
//! // Read, parse and build a zone.
//! let reader = inplace::Zonefile::load(&mut zone_bytes).unwrap();
//! let parsed = parsed::Zonefile::try_from(reader).unwrap();
//! let builder = ZoneBuilder::try_from(parsed).unwrap();
//!
//! // Verify that the zone apex name matches that of the imported data.
//! assert_eq!(&format!("{}", builder.apex().name()), "example.com");
//!
//! // Turn the builder into a zone.
//! let zone = Zone::from(builder);
//!
//! // Equivalent but shorter:
//! let mut zone_bytes = std::io::BufReader::new(&zone_file[..]);
//! let reader = inplace::Zonefile::load(&mut zone_bytes).unwrap();
//! let zone = Zone::try_from(reader).unwrap();
//!
//! // Insert the zone into a zone tree.
//! let mut tree = ZoneTree::new();
//! tree.insert_zone(zone).unwrap();
//!
//! // Query the zone tree.
//! let qname = Dname::bytes_from_str("example.com").unwrap();
//! let qtype = Rtype::A;
//! let found_zone = tree.find_zone(&qname, Class::In).unwrap();
//! let res: Answer = found_zone.read().query(qname, qtype).unwrap();
//!
//! // Verify that we found a result.
//! assert_eq!(res.rcode(), Rcode::NoError);
//! ```
//!
//! [`Class`]: base::iana::Class
//! [`Rtype`]: base::iana::Rtype
//! [`Dname`]: base::iana::Dname
//! [`NoError`]: base::iana::code::Rcode::NoError
//! [`NxDomain`]: base::iana::code::Rcode::NxDomain
//! [`ZoneBuilder`]: in_memory::ZoneBuilder

mod answer;
mod in_memory;
mod traits;
mod tree;
mod types;
mod walk;
mod zone;

pub use self::answer::Answer;
pub use self::in_memory::{
    ReadZoneIter, ReadZoneQuery, StorableZoneApex, ZoneBuilder,
};
pub use self::traits::ZoneStore;
pub use self::tree::ZoneTree;
pub use self::types::{
    Rrset, SharedRr, SharedRrset, StoredDname, StoredRecord,
};
pub use self::walk::WalkOp;
pub use self::zone::Zone;
