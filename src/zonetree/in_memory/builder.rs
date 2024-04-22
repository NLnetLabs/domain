//! Builders for in-memory zones.

use std::sync::Arc;
use std::vec::Vec;

use crate::base::iana::Class;
use crate::base::name::{Label, ToName};
use crate::zonefile::error::{CnameError, OutOfZone, ZoneCutError};
use crate::zonetree::types::ZoneCut;
use crate::zonetree::{
    SharedRr, SharedRrset, StoredDname, StoredRecord, Zone,
};

use super::nodes::{Special, ZoneApex, ZoneNode};
use super::versioned::Version;

//------------ ZoneBuilder ---------------------------------------------------

/// A builder of in-memory [`Zone`]s.
///
/// `ZoneBuilder` is used to specify the content of a single zone one,
/// resource record or RRset at a time, and to then turn that specification
/// into a populated in-memory [`Zone`].
///
/// <div class="warning">
///
/// Already have a zonefile in [presentation format]?
///
/// Check out the example [module docs] which shows how to use
/// [`inplace::Zonefile`], [`parsed::Zonefile`] and `ZoneBuilder` together
/// without having to manually insert each resource record into the
/// `ZoneBuilder` yourself.
///
/// </div>
///
/// Each `ZoneBuilder` builds a single zone with a named apex and a single
/// [`Class`]. All resource records within the zone are considered to have the
/// specified class.
///
/// `ZoneBuilder` has dedicated functions for inserting certain kinds of
/// resource record properly into the zone in order to cater to RR types that
/// require or benefit from special handling when [`ReadableZone::query`] is
/// invoked for the zone.
///
/// # Usage
///
/// To use `ZoneBuilder`:
/// - Call [`ZoneBuilder::new`] to create a new builder.
/// - Call the various `insert_()` functions to add as many resource records
/// as needed.
/// - Call [`ZoneBuilder::build`] to exchange the builder for a populated
///   [`Zone`].
///
/// [module docs]: crate::zonetree
/// [`inplace::Zonefile`]: crate::zonefile::inplace::Zonefile
/// [`parsed::Zonefile`]: crate::zonefile::parsed::Zonefile
/// [presentation format]:
///     https://datatracker.ietf.org/doc/html/rfc9499#section-2-1.16.1.6.1.3
/// [`ReadableZone::query`]: crate::zonetree::ReadableZone::query()
pub struct ZoneBuilder {
    apex: ZoneApex,
}

impl ZoneBuilder {
    /// Creates a new builder for the specified apex name and class.
    ///
    /// All resource records in the zone will be considered to have the
    /// specified [`Class`].
    #[must_use]
    pub fn new(apex_name: StoredDname, class: Class) -> Self {
        ZoneBuilder {
            apex: ZoneApex::new(apex_name, class),
        }
    }

    /// Builds an in-memory [`Zone`] from this builder.
    ///
    /// Calling this function consumes the [`ZoneBuilder`]. The returned
    /// `Zone` will be populated with the resource records that were inserted
    /// into the builder.
    #[must_use]
    pub fn build(self) -> Zone {
        Zone::new(self.apex)
    }

    /// Inserts a related set of resource records.
    ///
    /// Inserts a [`SharedRrset`] for the given owner name.
    pub fn insert_rrset(
        &mut self,
        name: &impl ToName,
        rrset: SharedRrset,
    ) -> Result<(), OutOfZone> {
        match self.get_node(self.apex.prepare_name(name)?) {
            Ok(node) => node.rrsets().update(rrset, Version::default()),
            Err(apex) => apex.rrsets().update(rrset, Version::default()),
        }
        Ok(())
    }

    /// Insert one or more resource records that represent a zone cut.
    ///
    /// A zone cut is the _"delimitation point between two zones where the
    /// origin of one of the zones is the child of the other zone"_ ([RFC 9499
    /// section 7.2.13]).
    ///
    /// Several different resource record types may appear at a zone cut and
    /// may be inserted into the `ZoneBuilder` using this function:
    ///
    /// - [Ns] records
    /// - [Ds] records
    /// - Glue records _(see [RFC 9499 section 7.2.30])_
    ///
    /// [Ns]: crate::rdata::rfc1035::Ns
    /// [Ds]: crate::rdata::dnssec::Ds
    /// [RFC 9499 section 7.2.13]:
    ///     https://datatracker.ietf.org/doc/html/rfc9499#section-7-2.13
    /// [delegation point]:
    ///     https://datatracker.ietf.org/doc/html/rfc4033#section-2
    pub fn insert_zone_cut(
        &mut self,
        name: &impl ToName,
        ns: SharedRrset,
        ds: Option<SharedRrset>,
        glue: Vec<StoredRecord>,
    ) -> Result<(), ZoneCutError> {
        let node = self.get_node(self.apex.prepare_name(name)?)?;
        let cut = ZoneCut {
            name: name.to_bytes(),
            ns,
            ds,
            glue,
        };
        node.update_special(Version::default(), Some(Special::Cut(cut)));
        Ok(())
    }

    /// Inserts a CNAME resource record.
    ///
    /// See: [`Cname`]
    ///
    /// [`Cname`]: crate::rdata::rfc1035::Cname
    pub fn insert_cname(
        &mut self,
        name: &impl ToName,
        cname: SharedRr,
    ) -> Result<(), CnameError> {
        let node = self.get_node(self.apex.prepare_name(name)?)?;
        node.update_special(Version::default(), Some(Special::Cname(cname)));
        Ok(())
    }

    fn get_node<'l>(
        &self,
        mut name: impl Iterator<Item = &'l Label>,
    ) -> Result<Arc<ZoneNode>, &ZoneApex> {
        let label = match name.next() {
            Some(label) => label,
            None => return Err(&self.apex),
        };
        let mut node = self
            .apex
            .children()
            .with_or_default(label, |node, _| node.clone());
        for label in name {
            node = node
                .children()
                .with_or_default(label, |node, _| node.clone());
        }
        Ok(node)
    }
}
