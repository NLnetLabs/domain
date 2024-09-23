#![cfg(feature = "unstable-zonetree")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-zonetree")))]
#![warn(missing_docs)]
//! Experimental storing and querying of zones and zone trees.
//!
//! # Zone trees
//!
//! A [`ZoneTree`] is a multi-rooted hierarchy of [`Zone`]s, each root being
//! the apex of a subtree for a distinct [`Class`]. `Zone`s can be inserted
//! and removed from the tree, looked up by containing or exact name, and the
//! set of zones in the tree can be iterated over.
//!
//! # Zones
//!
//! The `Zone`s that a tree is comprised of can be created by feeding
//! zonefiles or individual resource records into [`ZoneBuilder`] and then
//! inserted into a `ZoneTree`. `Zone`s can also be used directly without
//! inserting them into a `ZoneTree`.
//!
//! `Zone`s can be queried via their [read interface][traits::ReadableZone] by
//! [`Class`], [`Rtype`] and [`Name`] to produce an [`Answer`], which in turn
//! can be used to produce a response [`Message`] for serving to a DNS client.
//! Entire `Zone`s can also be [`walk`]ed to inspect or export their content.
//!
//! Updating a zone can be done via the low-level [`WritableZone`] interface
//! or using a higher-level helper like the [`ZoneUpdater`]. Updates to a
//! `Zone` can be captured as difference sets which for example can be used to
//! respond to IXFR queries.
//!
//! # Backing stores
//!
//! By default `Zone`s are stored in memory only. Zones with other types of
//! backing store can be created by implementing the [`ZoneStore`] trait and
//! passing an instance of the implementing struct to [`Zone::new`]. Zones
//! with different backing store types can be mixed and matched within the
//! same tree. Backing stores can be synchronous or asynchronous, the latter
//! being useful for a remote backing store such as a distributed database.
//!
//! The default in-memory zone implementation uses an append only write
//! strategy with new zone versions only becoming visible to consumers on
//! commit and existing zone versions remaining readable during write
//! operations.
//!
//! # Usage
//!
//! The example below shows how to populate a [`ZoneTree`] from a zonefile.
//! For more examples of using [`Zone`]s and [`ZoneTree`]s including
//! implementing an alternate zone backing store for your [`Zone`]s, see the
//! [examples in the GitHub
//! repository](https://github.com/NLnetLabs/domain/tree/main/examples).
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
//! [`query`]: ReadableZone::query
//! [`walk`]: ReadableZone::walk
//! [`Class`]: crate::base::iana::Class
//! [`Rtype`]: crate::base::iana::Rtype
//! [`Name`]: crate::base::name::Name
//! [`Message`]: crate::base::Message
//! [`NoError`]: crate::base::iana::code::Rcode::NOERROR
//! [`NxDomain`]: crate::base::iana::code::Rcode::NXDOMAIN
//! [`ZoneBuilder`]: in_memory::ZoneBuilder
//! [`ZoneUpdater`]: update::ZoneUpdater

mod answer;
pub mod error;
mod in_memory;
pub mod parsed;
mod traits;
mod tree;
pub mod types;
pub mod update;
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
    ZoneDiffBuilder,
};
pub use self::walk::WalkOp;
pub use self::zone::{Zone, ZoneKey};

/// Zone related utilities.
pub mod util {
    use crate::base::name::{Label, ToLabelIter};
    use crate::base::ToName;

    use super::error::OutOfZone;
    use super::StoredName;

    /// Gets a reverse iterator to the relative part of a name.
    ///
    /// Can be used for example to get an iterator over the part of a name
    /// that is "under" a zone apex name.
    pub fn rel_name_rev_iter<'l>(
        base: &StoredName,
        qname: &'l impl ToName,
    ) -> Result<impl Iterator<Item = &'l Label> + Clone, OutOfZone> {
        let mut qname = qname.iter_labels().rev();
        for apex_label in base.iter_labels().rev() {
            let qname_label = qname.next();
            if Some(apex_label) != qname_label {
                return Err(OutOfZone);
            }
        }
        Ok(qname)
    }
}
