//! The nodes in a zone tree.

use super::read::{ReadableZone, WalkState};
use super::rrset::{SharedRr, SharedRrset, StoredDname, StoredRecord};
use super::versioned::{Version, Versioned};
use super::write::{WriteZone, WriteableZone};
use super::zone::{VersionMarker, ZoneData, ZoneVersions};
use super::ReadZone;
use crate::base::iana::{Class, Rtype};
use crate::base::name::{Label, OwnedLabel, ToDname, ToLabelIter};
use parking_lot::{
    RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::boxed::Box;
use std::collections::{hash_map, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::string::String;
use std::string::ToString;
use std::sync::Arc;
use std::vec::Vec;
use tokio::sync::Mutex;

//------------ ZoneApex ------------------------------------------------------

#[derive(Debug)]
pub struct ZoneApex {
    apex_name: StoredDname,
    apex_name_display: String,
    class: Class,
    rrsets: NodeRrsets,
    children: NodeChildren,
    update_lock: Arc<Mutex<()>>,
}

impl ZoneApex {
    /// Creates a new apex.
    pub fn new(apex_name: StoredDname, class: Class) -> Self {
        ZoneApex {
            apex_name_display: format!("{}", apex_name),
            apex_name,
            class,
            rrsets: Default::default(),
            children: Default::default(),
            update_lock: Default::default(),
        }
    }

    /// Creates a new apex.
    pub fn from_parts(
        apex_name: StoredDname,
        class: Class,
        rrsets: NodeRrsets,
        children: NodeChildren,
    ) -> Self {
        ZoneApex {
            apex_name_display: format!("{}", apex_name),
            apex_name,
            class,
            rrsets,
            children,
            update_lock: Default::default(),
        }
    }

    /// Returns the string version of the apex name.
    pub fn apex_name_display(&self) -> &str {
        &self.apex_name_display
    }

    /// Returns the class name.
    pub fn display_class(&self) -> Cow<str> {
        match self.class() {
            Class::In => Cow::Borrowed("IN"),
            class => Cow::Owned(class.to_string()),
        }
    }

    pub fn prepare_name<'l>(
        &self,
        qname: &'l impl ToDname,
    ) -> Result<impl Iterator<Item = &'l Label> + Clone, OutOfZone> {
        let mut qname = qname.iter_labels().rev();
        for apex_label in self.apex_name().iter_labels().rev() {
            let qname_label = qname.next();
            if Some(apex_label) != qname_label {
                return Err(OutOfZone);
            }
        }
        Ok(qname)
    }

    /// Returns the RRsets of this node.
    pub fn rrsets(&self) -> &NodeRrsets {
        &self.rrsets
    }

    /// Returns the SOA record for the given version if available.
    pub fn get_soa(&self, version: Version) -> Option<SharedRr> {
        self.rrsets()
            .get(Rtype::Soa, version)
            .and_then(|rrset| rrset.first())
    }

    /// Returns the children.
    pub fn children(&self) -> &NodeChildren {
        &self.children
    }

    pub fn rollback(&self, version: Version) {
        self.rrsets.rollback(version);
        self.children.rollback(version);
    }

    pub fn clean(&self, version: Version) {
        self.rrsets.clean(version);
        self.children.clean(version);
    }
}

//--- impl ZoneData

impl ZoneData for ZoneApex {
    fn class(&self) -> Class {
        self.class
    }

    fn apex_name(&self) -> &StoredDname {
        &self.apex_name
    }

    fn read(
        self: Arc<Self>,
        current: (Version, Arc<VersionMarker>),
    ) -> Box<dyn ReadableZone> {
        let (version, marker) = current;
        Box::new(ReadZone::new(self, version, marker))
    }

    fn write(
        self: Arc<Self>,
        version: Version,
        zone_versions: Arc<RwLock<ZoneVersions>>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WriteableZone>>>> {
        Box::pin(async move {
            let lock = self.update_lock.clone().lock_owned().await;
            Box::new(WriteZone::new(self, lock, version, zone_versions))
                as Box<dyn WriteableZone>
        })
    }
}

//------------ ZoneNode ------------------------------------------------------

#[derive(Default, Debug)]
pub struct ZoneNode {
    /// The RRsets of the node.
    rrsets: NodeRrsets,

    /// The special functions of the node.
    special: RwLock<Versioned<Option<Special>>>,

    /// The child nodes of the node.
    children: NodeChildren,
}

impl ZoneNode {
    /// Returns the RRsets of this node.
    pub fn rrsets(&self) -> &NodeRrsets {
        &self.rrsets
    }

    /// Returns whether the node is NXDomain for a version.
    pub fn is_nx_domain(&self, version: Version) -> bool {
        self.with_special(version, |special| {
            matches!(special, Some(Special::NxDomain))
        })
    }

    pub fn with_special<R>(
        &self,
        version: Version,
        op: impl FnOnce(Option<&Special>) -> R,
    ) -> R {
        op(self.special.read().get(version).and_then(Option::as_ref))
    }

    /// Updates the special.
    pub fn update_special(&self, version: Version, special: Option<Special>) {
        self.special.write().update(version, special)
    }

    /// Returns the children.
    pub fn children(&self) -> &NodeChildren {
        &self.children
    }

    pub fn rollback(&self, version: Version) {
        self.rrsets.rollback(version);
        self.special.write().rollback(version);
        self.children.rollback(version);
    }

    pub fn clean(&self, version: Version) {
        self.rrsets.clean(version);
        self.special.write().clean(version);
        self.children.clean(version);
    }
}

//------------ NodeRrsets ----------------------------------------------------

#[derive(Default, Debug)]
pub struct NodeRrsets {
    rrsets: RwLock<HashMap<Rtype, NodeRrset>>,
}

impl NodeRrsets {
    /// Returns whether there are no RRsets for the given version.
    pub fn is_empty(&self, version: Version) -> bool {
        let rrsets = self.rrsets.read();
        if rrsets.is_empty() {
            return true;
        }
        for value in self.rrsets.read().values() {
            if value.get(version).is_some() {
                return false;
            }
        }
        true
    }

    /// Returns the RRset for a given record type.
    pub fn get(&self, rtype: Rtype, version: Version) -> Option<SharedRrset> {
        self.rrsets
            .read()
            .get(&rtype)
            .and_then(|rrsets| rrsets.get(version))
            .cloned()
    }

    /// Updates an RRset.
    pub fn update(&self, rrset: SharedRrset, version: Version) {
        self.rrsets
            .write()
            .entry(rrset.rtype())
            .or_default()
            .update(rrset, version)
    }

    /// Removes the RRset for the given type.
    pub fn remove(&self, rtype: Rtype, version: Version) {
        self.rrsets
            .write()
            .entry(rtype)
            .or_default()
            .remove(version)
    }

    pub fn rollback(&self, version: Version) {
        self.rrsets
            .write()
            .values_mut()
            .for_each(|rrset| rrset.rollback(version));
    }

    pub fn clean(&self, version: Version) {
        self.rrsets
            .write()
            .values_mut()
            .for_each(|rrset| rrset.clean(version));
    }

    pub(super) fn iter(&self) -> NodeRrsetsIter {
        NodeRrsetsIter::new(self.rrsets.read())
    }
}

//------------ NodeRrsetIter -------------------------------------------------

pub(super) struct NodeRrsetsIter<'a> {
    guard: RwLockReadGuard<'a, HashMap<Rtype, NodeRrset>>,
}

impl<'a> NodeRrsetsIter<'a> {
    fn new(guard: RwLockReadGuard<'a, HashMap<Rtype, NodeRrset>>) -> Self {
        Self { guard }
    }

    pub fn iter(&self) -> hash_map::Iter<'_, Rtype, NodeRrset> {
        self.guard.iter()
    }
}

//------------ NodeRrset -----------------------------------------------------

#[derive(Default, Debug)]
pub(crate) struct NodeRrset {
    /// The RRsets for the various versions.
    rrsets: Versioned<SharedRrset>,
}

impl NodeRrset {
    pub fn get(&self, version: Version) -> Option<&SharedRrset> {
        self.rrsets.get(version)
    }

    fn update(&mut self, rrset: SharedRrset, version: Version) {
        self.rrsets.update(version, rrset)
    }

    fn remove(&mut self, version: Version) {
        self.rrsets.clean(version)
    }

    pub fn rollback(&mut self, version: Version) {
        self.rrsets.rollback(version);
    }

    pub fn clean(&mut self, version: Version) {
        self.rrsets.rollback(version);
    }
}

//------------ Special -------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Special {
    Cut(ZoneCut),
    Cname(SharedRr),
    NxDomain,
}

//------------ ZoneCut -------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ZoneCut {
    pub name: StoredDname,
    pub ns: SharedRrset,
    pub ds: Option<SharedRrset>,
    pub glue: Vec<StoredRecord>,
}

//------------ NodeChildren --------------------------------------------------

#[derive(Debug, Default)]
pub struct NodeChildren {
    children: RwLock<HashMap<OwnedLabel, Arc<ZoneNode>>>,
}

impl NodeChildren {
    pub fn with<R>(
        &self,
        label: &Label,
        op: impl FnOnce(Option<&Arc<ZoneNode>>) -> R,
    ) -> R {
        op(self.children.read().get(label))
    }

    /// Executes a closure for a child, creating a new one of necessary.
    ///
    /// The closure receives a references to the node and a boolean
    /// expressing whether the child was created.
    pub fn with_or_default<R>(
        &self,
        label: &Label,
        op: impl FnOnce(&Arc<ZoneNode>, bool) -> R,
    ) -> R {
        let lock = self.children.upgradable_read();
        if let Some(node) = lock.get(label) {
            return op(node, false);
        }
        let mut lock = RwLockUpgradableReadGuard::upgrade(lock);
        lock.insert(label.into(), Default::default());
        let lock = RwLockWriteGuard::downgrade(lock);
        op(lock.get(label).unwrap(), true)
    }

    fn rollback(&self, version: Version) {
        self.children
            .read()
            .values()
            .for_each(|item| item.rollback(version))
    }

    fn clean(&self, version: Version) {
        self.children
            .read()
            .values()
            .for_each(|item| item.clean(version))
    }

    pub(super) fn walk(
        &self,
        walk: WalkState,
        op: impl Fn(WalkState, (&OwnedLabel, &Arc<ZoneNode>)),
    ) {
        for child in self.children.read().iter() {
            (op)(walk.clone(), child)
        }
    }
}

//============ Error Types ==================================================

/// A domain name is not under the zone’s apex.
#[derive(Clone, Copy, Debug)]
pub struct OutOfZone;
