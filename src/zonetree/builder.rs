//! Building a new zone.

use std::sync::Arc;
use std::vec::Vec;

use super::nodes::{OutOfZone, Special, ZoneApex, ZoneCut, ZoneNode};
use super::rrset::{SharedRr, SharedRrset, StoredDname, StoredRecord};
use super::set::{InsertZoneError, ZoneSet};
use super::versioned::Version;
use super::zone::Zone;
use crate::base::iana::Class;
use crate::base::name::{Label, ToDname};

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
        zone_set: &mut ZoneSet,
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

#[derive(Clone, Copy, Debug)]
pub enum ZoneCutError {
    OutOfZone,
    ZoneCutAtApex,
}

impl From<OutOfZone> for ZoneCutError {
    fn from(_: OutOfZone) -> ZoneCutError {
        ZoneCutError::OutOfZone
    }
}

impl<'a> From<&'a ZoneApex> for ZoneCutError {
    fn from(_: &'a ZoneApex) -> ZoneCutError {
        ZoneCutError::ZoneCutAtApex
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CnameError {
    OutOfZone,
    CnameAtApex,
}

impl From<OutOfZone> for CnameError {
    fn from(_: OutOfZone) -> CnameError {
        CnameError::OutOfZone
    }
}

impl<'a> From<&'a ZoneApex> for CnameError {
    fn from(_: &'a ZoneApex) -> CnameError {
        CnameError::CnameAtApex
    }
}
