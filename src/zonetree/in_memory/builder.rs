//! Builders for in-memory zones.

use std::sync::Arc;
use std::vec::Vec;

use crate::base::iana::Class;
use crate::base::name::{Label, ToDname};
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
/// [`ZoneBuilder`] is used to build [`Zone`]s that use the default in-memory
/// backing store. It has dedicated functions for inserting certain kinds of
/// resource record properly into the zone in order to cater to RR types that
/// require or benefit from special handling when is [`ReadableZone::query()`]
/// invoked for the zone.
///
/// Each [`ZoneBuilder`] builds a single zone with a named apex and a single
/// class. All resource records within the zone are considered to have the
/// specified class.
///
/// # Usage
///
/// To use a [`ZoneBuilder`]:
/// - Call [`ZoneBuilder::new()`] to create a new builder.
/// - Call the various `insert_()` functions to add as many resource records
/// as needed.
/// - Call [`ZoneBuilder::build()`] to exchange the builder for a populated
///   [`Zone`].
///
/// [`ReadableZone::query()`]: crate::zonetree::ReadableZone::query()
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

    /// Builds a [`Zone`] from this builder.
    ///
    /// Calling this function consumes the [`ZoneBuilder`]. The returned
    /// in-memory [`Zone`] will be populated with the resource records that
    /// were inserted into the builder.
    #[must_use]
    pub fn build(self) -> Zone {
        Zone::new(self.apex)
    }

    /// Inserts a related set of resource records.
    ///
    /// Inserts a [`SharedRrset`] for the given owner name.
    pub fn insert_rrset(
        &mut self,
        name: &impl ToDname,
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
    /// Per [RFC 9499 section 7.2.13] a zone cut is the _"delimitation point
    /// between two zones where the origin of one of the zones is the child of
    /// the other zone"_.
    ///
    /// Originally the _"existence of a zone cut [was] indicated in the parent
    /// zone by the existence of NS records specifying the origin of the child
    /// zone"_ ([RFC 1034 section 4.2], [RFC 2181 section 6]).
    ///
    /// When these NS records specify that _"the name server's name is 'below'
    /// the cut"_ they are one form of what is referred to as "glue" ([RFC
    /// 9499 section 7.2.30]).
    ///
    /// Additionally, DNSSEC introduced the Delegation Signer (DS) record
    /// which _"resides at a [delegation point] in a parent zone"_ ([RFC 4033
    /// section 3.1]).
    ///
    /// The [`ZoneBuilder`] and in-memory [`Zone`]s are aware of these
    /// differences and thus this function requires you to specify them
    /// separately and explicitly.
    ///
    /// [RFC 1034 section 4.2]:
    ///     https://www.rfc-editor.org/rfc/rfc1034#section-4.2
    /// [RFC 2181 section 6]: https://www.rfc-editor.org/rfc/rfc2181#section-6
    /// [RFC 4033 section 3.1]:
    ///     https://datatracker.ietf.org/doc/html/rfc4033#section-3.1
    /// [RFC 9499 section 7.2.13]:
    ///     https://datatracker.ietf.org/doc/html/rfc9499#section-7-2.13
    /// [RFC 9499 section 7.2.30]:
    ///     https://datatracker.ietf.org/doc/html/rfc9499#section-7-2.30
    /// [delegation point]:
    ///     https://datatracker.ietf.org/doc/html/rfc4033#section-2
    pub fn insert_zone_cut(
        &mut self,
        name: &impl ToDname,
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
    /// Inserts a CNAME record ([RFC 1035 section 3.2.2]). See also [RFC 9499
    /// section 2.1.43].
    ///
    /// [RFC 1035 section 3.2.2]:
    ///     view-source:https://www.ietf.org/rfc/rfc1035.html#section-3.2.2
    /// [RFC 9499 section 2.1.43]:
    ///     https://datatracker.ietf.org/doc/html/rfc9499#section-2-1.43
    pub fn insert_cname(
        &mut self,
        name: &impl ToDname,
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
