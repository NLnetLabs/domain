#![cfg(feature = "unstable-zonetree")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-zonetree")))]
#![warn(missing_docs)]
//! Storing and querying of zone trees.
//!
//! A [`ZoneTree`] represents a multi-rooted hierarchy of [`Zone`]s, one
//! subtree per [`Class`], which can then be queried by [`Class`], [`Rtype`]
//! and [`Dname`] to obtain [`Answer`]s, successful ([`NoError`]) or otherwise
//! (e.g. [`NxDomain`]).
//!
//! For diagnostic and export (e.g. zone transfer) purposes zones, and trees
//! also support iteration.
//!
//! Use [`ZoneBuilder`] to easily construct an in-memory [`Zone`] from given
//! DNS records, or implement the [`ZoneStore`] trait to enable construction
//! of zones backed by your own choice of storage.
//!
//! For an example of implementing an alternate zone backing store see
//! `examples/other/mysql-zone.rs`.
//!
//! # Using the in-memory store
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
//! // Verify that the zone origin matches that of the imported data.
//! assert_eq!(&format!("{}", builder.apex().origin()), "example.com");
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
pub use self::in_memory::ZoneBuilder;
pub use self::traits::{
    ReadableZone, WritableZone, WritableZoneNode, ZoneStore,
};
pub use self::tree::{ZoneExists, ZoneTree};
pub use self::types::{
    Rrset, SharedRr, SharedRrset, StoredDname, StoredRecord,
};
pub use self::walk::WalkOp;
pub use self::zone::Zone;
