//! Building a new zone.

use std::sync::Arc;
use std::vec::Vec;

use crate::base::iana::Class;
use crate::base::name::{Label, ToDname};
use crate::zonefile::error::{CnameError, OutOfZone, ZoneCutError};
use crate::zonefile::parsed;
use crate::zonetree::tree::InsertZoneError;
use crate::zonetree::types::ZoneCut;
use crate::zonetree::{
    SharedRr, SharedRrset, StoredDname, StoredRecord, Zone, ZoneTree,
};

use super::nodes::{Special, ZoneApex, ZoneNode};
use super::versioned::Version;

//------------ ZoneBuilder ---------------------------------------------------

pub struct ZoneBuilder {
    apex: ZoneApex,
}

impl ZoneBuilder {
    pub fn new(apex_name: StoredDname, class: Class) -> Self {
        ZoneBuilder {
            apex: ZoneApex::new(apex_name, class),
        }
    }

    pub fn finalize(self) -> Zone {
        Zone::new(self.apex)
    }

    pub fn finalize_into_set(
        self,
        zone_set: &mut ZoneTree,
    ) -> Result<(), InsertZoneError> {
        zone_set.insert_zone(self.finalize())
    }

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

//--- TryFrom<parsed::Zonefile>

impl TryFrom<parsed::Zonefile> for ZoneBuilder {
    type Error = parsed::ZoneError;

    fn try_from(source: parsed::Zonefile) -> Result<Self, Self::Error> {
        source.into_zone_builder()
    }
}
