//! The known set of zones.

use super::zone::Zone;
use crate::base::iana::Class;
use crate::base::name::{Label, OwnedLabel, ToDname, ToLabelIter};
use std::collections::hash_map;
use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::vec::Vec;

//------------ ZoneTree ------------------------------------------------------

/// A multi-rooted [`Zone`] hierarchy.
///
/// [`Zone`]: crate::zonetree::Zone.
#[derive(Default)]
pub struct ZoneTree {
    roots: Roots,
}

impl ZoneTree {
    /// Creates an empty [`ZoneTree`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Gets a [`Zone`] for the given apex name and CLASS, if any.
    pub fn get_zone(
        &self,
        apex_name: &impl ToDname,
        class: Class,
    ) -> Option<&Zone> {
        self.roots
            .get(class)?
            .get_zone(apex_name.iter_labels().rev())
    }

    /// Inserts the given [`Zone`].
    ///
    /// Returns a [`ZoneTreeModificationError`] if a zone with the same apex
    /// and CLASS already exists in the tree.
    pub fn insert_zone(
        &mut self,
        zone: Zone,
    ) -> Result<(), ZoneTreeModificationError> {
        self.roots.get_or_insert(zone.class()).insert_zone(
            &mut zone.apex_name().clone().iter_labels().rev(),
            zone,
        )
    }

    /// Gets the closest matching [`Zone`] for the given QNAME and CLASS, if
    /// any.
    pub fn find_zone(
        &self,
        qname: &impl ToDname,
        class: Class,
    ) -> Option<&Zone> {
        self.roots.get(class)?.find_zone(qname.iter_labels().rev())
    }

    /// Returns an iterator over all of the [`Zone`]s in the tree.
    pub fn iter_zones(&self) -> ZoneSetIter {
        ZoneSetIter::new(self)
    }

    /// Removes the specified [`Zone`], if any.
    pub fn remove_zone(
        &mut self,
        apex_name: &impl ToDname,
        class: Class,
    ) -> Result<(), ZoneTreeModificationError> {
        if let Some(root) = self.roots.get_mut(class) {
            root.remove_zone(apex_name.iter_labels().rev())
        } else {
            Err(ZoneTreeModificationError::ZoneDoesNotExist)
        }
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

    pub fn get_mut(&mut self, class: Class) -> Option<&mut ZoneSetNode> {
        if class == Class::In {
            Some(&mut self.in_)
        } else {
            self.others.get_mut(&class)
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

    fn insert_zone<'l>(
        &mut self,
        mut apex_name: impl Iterator<Item = &'l Label>,
        zone: Zone,
    ) -> Result<(), ZoneTreeModificationError> {
        if let Some(label) = apex_name.next() {
            self.children
                .entry(label.into())
                .or_default()
                .insert_zone(apex_name, zone)
        } else if self.zone.is_some() {
            Err(ZoneTreeModificationError::ZoneExists)
        } else {
            self.zone = Some(zone);
            Ok(())
        }
    }

    fn remove_zone<'l>(
        &mut self,
        mut apex_name: impl Iterator<Item = &'l Label>,
    ) -> Result<(), ZoneTreeModificationError> {
        match apex_name.next() {
            Some(label) => {
                if self.children.remove(label).is_none() {
                    return Err(ZoneTreeModificationError::ZoneDoesNotExist);
                }
            }
            None => {
                self.zone = None;
            }
        }
        Ok(())
    }
}

//------------ ZoneSetIter ---------------------------------------------------

pub struct ZoneSetIter<'a> {
    roots: hash_map::Values<'a, Class, ZoneSetNode>,
    nodes: NodesIter<'a>,
}

impl<'a> ZoneSetIter<'a> {
    fn new(set: &'a ZoneTree) -> Self {
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
pub enum ZoneTreeModificationError {
    ZoneExists,
    ZoneDoesNotExist,
    Io(io::Error),
}

impl From<io::Error> for ZoneTreeModificationError {
    fn from(src: io::Error) -> Self {
        ZoneTreeModificationError::Io(src)
    }
}

impl From<ZoneTreeModificationError> for io::Error {
    fn from(src: ZoneTreeModificationError) -> Self {
        match src {
            ZoneTreeModificationError::Io(err) => err,
            ZoneTreeModificationError::ZoneDoesNotExist => {
                io::Error::new(io::ErrorKind::Other, "zone does not exist")
            }
            ZoneTreeModificationError::ZoneExists => {
                io::Error::new(io::ErrorKind::Other, "zone exists")
            }
        }
    }
}

impl Display for ZoneTreeModificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneTreeModificationError::ZoneExists => {
                write!(f, "Zone already exists")
            }
            ZoneTreeModificationError::ZoneDoesNotExist => {
                write!(f, "Zone does not exist")
            }
            ZoneTreeModificationError::Io(err) => {
                write!(f, "Io error: {err}")
            }
        }
    }
}
