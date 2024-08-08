#![cfg(feature = "unstable-zonetree")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-zonetree")))]
#![warn(missing_docs)]
//! Experimental storing and querying of zone trees.
//!
//! A [`ZoneTree`] is a multi-rooted hierarchy of [`Zone`]s, each root being
//! the apex of a subtree for a distinct [`Class`].
//!
//! Individual `Zone`s within the tree can be looked up by containing or exact
//! name, and then one can [`query`] the found `Zone` by [`Class`], [`Rtype`] and
//! [`Name`] to produce an [`Answer`], which in turn can be used to produce a
//! response [`Message`] for serving to a DNS client.
//!
//! Trees can also be iterated over to inspect or export their content.
//!
//! The `Zone`s that a tree is comprised of can be created by feeding
//! zonefiles or individual resource records into [`ZoneBuilder`] and then
//! inserted into a `ZoneTree`.
//!
//! By default `Zone`s are stored in memory only. Zones with other types of
//! backing store can be created by implementing the [`ZoneStore`] trait and
//! passing an instance of the implementing struct to [`Zone::new`]. Zones
//! with different backing store types can be mixed and matched within the
//! same tree.
//!
//! The example below shows how to populate a [`ZoneTree`] from a zonefile. For
//! more examples of using [`Zone`]s and [`ZoneTree`]s including implementing an
//! alternate zone backing store for your [`Zone`]s, see the
//! [examples in the GitHub repository](https://github.com/NLnetLabs/domain/tree/main/examples).
//!
//! # Usage
//!
//! The following example builds and queries a [`ZoneTree`] containing a
//! single in-memory [`Zone`].
//!
//! ```
//! use domain::base::iana::{Class, Rcode, Rtype};
//! use domain::base::name::Name;
//! use domain::zonefile::inplace;
//! use domain::zonetree::parsed;
//! use domain::zonetree::{Answer, Zone, ZoneBuilder, ZoneTree};
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
//! let qname = Name::bytes_from_str("example.com").unwrap();
//! let qtype = Rtype::A;
//! let found_zone = tree.find_zone(&qname, Class::IN).unwrap();
//! let res: Answer = found_zone.read().query(qname, qtype).unwrap();
//!
//! // Verify that we found a result.
//! assert_eq!(res.rcode(), Rcode::NOERROR);
//! ```
//!
//! [`query`]: crate::zonetree::ReadableZone::query
//! [`Class`]: crate::base::iana::Class
//! [`Rtype`]: crate::base::iana::Rtype
//! [`Name`]: crate::base::name::Name
//! [`Message`]: crate::base::Message
//! [`NoError`]: crate::base::iana::code::Rcode::NOERROR
//! [`NxDomain`]: crate::base::iana::code::Rcode::NXDOMAIN
//! [`ZoneBuilder`]: in_memory::ZoneBuilder

mod answer;
pub mod error;
mod in_memory;
pub mod parsed;
mod traits;
mod tree;
pub mod types;
mod walk;
mod zone;

pub use self::answer::{Answer, AnswerAuthority, AnswerContent};
pub use self::in_memory::ZoneBuilder;
pub use self::traits::{
    ReadableZone, WritableZone, WritableZoneNode, ZoneStore,
};
pub use self::tree::{ZoneSetIter, ZoneTree};
pub use self::types::{
    Rrset, SharedRr, SharedRrset, StoredName, StoredRecord, ZoneDiff,
};
pub use self::walk::WalkOp;
pub use self::zone::{Zone, ZoneKey};
