//! The known set of zones.

use super::zone::Zone;
use crate::base::iana::Class;
use crate::base::name::{Label, OwnedLabel, ToDname, ToLabelIter};
use std::collections::hash_map;
use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::vec::Vec;

//------------ ZoneSet -------------------------------------------------------

/// The set of zones we are authoritative for.
#[derive(Default)]
pub struct ZoneSet {
    roots: Roots,
}

impl ZoneSet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get_zone(
        &self,
        apex_name: &impl ToDname,
        class: Class,
    ) -> Option<&Zone> {
        self.roots
            .get(class)?
            .get_zone(apex_name.iter_labels().rev())
    }

    pub fn insert_zone(&mut self, zone: Zone) -> Result<(), InsertZoneError> {
        self.roots.get_or_insert(zone.class()).insert_zone(
            &mut zone.apex_name().clone().iter_labels().rev(),
            zone,
        )
    }

    pub fn find_zone(
        &self,
        qname: &impl ToDname,
        class: Class,
    ) -> Option<&Zone> {
        self.roots.get(class)?.find_zone(qname.iter_labels().rev())
    }

    pub fn iter_zones(&self) -> ZoneSetIter {
        ZoneSetIter::new(self)
    }
}

//------------ Roots ---------------------------------------------------------

#[derive(Default)]
struct Roots {
    in_: ZoneSetNode,
    others: HashMap<Class, ZoneSetNode>,
}

impl Roots {
    pub fn get(&self, class: Class) -> Option<&ZoneSetNode> {
        if class == Class::In {
            Some(&self.in_)
        } else {
            self.others.get(&class)
        }
    }

    pub fn get_or_insert(&mut self, class: Class) -> &mut ZoneSetNode {
        if class == Class::In {
            &mut self.in_
        } else {
            self.others.entry(class).or_default()
        }
    }
}

//------------ ZoneSetNode ---------------------------------------------------

#[derive(Default)]
struct ZoneSetNode {
    zone: Option<Zone>,
    children: HashMap<OwnedLabel, ZoneSetNode>,
}

impl ZoneSetNode {
    fn get_zone<'l>(
        &self,
        mut apex_name: impl Iterator<Item = &'l Label>,
    ) -> Option<&Zone> {
        match apex_name.next() {
            Some(label) => self.children.get(label)?.get_zone(apex_name),
            None => self.zone.as_ref(),
        }
    }

    pub fn find_zone<'l>(
        &self,
        mut qname: impl Iterator<Item = &'l Label>,
    ) -> Option<&Zone> {
        if let Some(label) = qname.next() {
            if let Some(node) = self.children.get(label) {
                if let Some(zone) = node.find_zone(qname) {
                    return Some(zone);
                }
            }
        }
        self.zone.as_ref()
    }

    // TODO: If this is not async, how will we persist the addition of this
    // zone in the backing store, e.g. a database? Should that actually be done
    // separately prior to calling this function and this is only about
    // updating the in-memory view of the set of zones in the backing store?
    fn insert_zone<'l>(
        &mut self,
        mut apex_name: impl Iterator<Item = &'l Label>,
        zone: Zone,
    ) -> Result<(), InsertZoneError> {
        if let Some(label) = apex_name.next() {
            self.children
                .entry(label.into())
                .or_default()
                .insert_zone(apex_name, zone)
        } else if self.zone.is_some() {
            Err(InsertZoneError::ZoneExists)
        } else {
            self.zone = Some(zone);
            Ok(())
        }
    }
}

//------------ ZoneSetIter ---------------------------------------------------

pub struct ZoneSetIter<'a> {
    roots: hash_map::Values<'a, Class, ZoneSetNode>,
    nodes: NodesIter<'a>,
}

impl<'a> ZoneSetIter<'a> {
    fn new(set: &'a ZoneSet) -> Self {
        ZoneSetIter {
            roots: set.roots.others.values(),
            nodes: NodesIter::new(&set.roots.in_),
        }
    }
}

impl<'a> Iterator for ZoneSetIter<'a> {
    type Item = &'a Zone;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(node) = self.nodes.next() {
                if let Some(zone) = node.zone.as_ref() {
                    return Some(zone);
                } else {
                    continue;
                }
            }
            self.nodes = NodesIter::new(self.roots.next()?);
        }
    }
}

//------------ NodesIter -----------------------------------------------------

struct NodesIter<'a> {
    root: Option<&'a ZoneSetNode>,
    stack: Vec<hash_map::Values<'a, OwnedLabel, ZoneSetNode>>,
}

impl<'a> NodesIter<'a> {
    fn new(node: &'a ZoneSetNode) -> Self {
        NodesIter {
            root: Some(node),
            stack: Vec::new(),
        }
    }

    fn next_node(&mut self) -> Option<&'a ZoneSetNode> {
        if let Some(node) = self.root.take() {
            return Some(node);
        }
        loop {
            if let Some(iter) = self.stack.last_mut() {
                if let Some(node) = iter.next() {
                    return Some(node);
                }
            } else {
                return None;
            }
            let _ = self.stack.pop();
        }
    }
}

impl<'a> Iterator for NodesIter<'a> {
    type Item = &'a ZoneSetNode;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next_node()?;
        self.stack.push(node.children.values());
        Some(node)
    }
}

//============ Error Types ===================================================

#[derive(Debug)]
pub enum InsertZoneError {
    ZoneExists,
    Io(io::Error),
}

impl From<io::Error> for InsertZoneError {
    fn from(src: io::Error) -> Self {
        InsertZoneError::Io(src)
    }
}

impl From<InsertZoneError> for io::Error {
    fn from(src: InsertZoneError) -> Self {
        match src {
            InsertZoneError::Io(err) => err,
            InsertZoneError::ZoneExists => {
                io::Error::new(io::ErrorKind::Other, "zone exists")
            }
        }
    }
}

impl Display for InsertZoneError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InsertZoneError::ZoneExists => write!(f, "Zone already exists"),
            InsertZoneError::Io(err) => write!(f, "Io error: {err}"),
        }
    }
}

pub struct ZoneExists; // XXX
