//! The nodes in a zone tree.

use std::boxed::Box;
use std::collections::{hash_map, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use parking_lot::{
    RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard,
};
use tokio::sync::Mutex;

use crate::base::iana::{Class, Rtype};
use crate::base::name::{Label, OwnedLabel, ToLabelIter, ToName};
use crate::zonetree::error::{CnameError, OutOfZone, ZoneCutError};
use crate::zonetree::types::{StoredName, ZoneCut};
use crate::zonetree::walk::WalkState;
use crate::zonetree::{
    ReadableZone, SharedRr, SharedRrset, WritableZone, ZoneStore,
};

use super::read::ReadZone;
use super::versioned::{Version, Versioned};
use super::write::{WriteZone, ZoneVersions};

//------------ ZoneApex ------------------------------------------------------

#[derive(Debug)]
pub struct ZoneApex {
    apex_name: StoredName,
    class: Class,
    rrsets: NodeRrsets,
    children: NodeChildren,
    update_lock: Arc<Mutex<()>>,
    versions: Arc<RwLock<ZoneVersions>>,
}

impl ZoneApex {
    /// Creates a new apex.
    pub fn new(apex_name: StoredName, class: Class) -> Self {
        ZoneApex {
            apex_name,
            class,
            rrsets: Default::default(),
            children: Default::default(),
            update_lock: Default::default(),
            versions: Default::default(),
        }
    }

    /// Creates a new apex.
    pub fn from_parts(
        apex_name: StoredName,
        class: Class,
        rrsets: NodeRrsets,
        children: NodeChildren,
        versions: ZoneVersions,
    ) -> Self {
        ZoneApex {
            apex_name,
            class,
            rrsets,
            children,
            update_lock: Default::default(),
            versions: Arc::new(RwLock::new(versions)),
        }
    }

    pub fn prepare_name<'l>(
        &self,
        qname: &'l impl ToName,
    ) -> Result<impl Iterator<Item = &'l Label> + Clone, OutOfZone> {
        let mut qname = qname.iter_labels().rev();
        for apex_label in self.name().iter_labels().rev() {
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
            .get(Rtype::SOA, version)
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

    pub fn remove_all(&self, version: Version) {
        self.rrsets.remove_all(version);
        self.children.remove_all(version);
    }

    pub fn versions(&self) -> &RwLock<ZoneVersions> {
        &self.versions
    }

    pub fn name(&self) -> &StoredName {
        &self.apex_name
    }
}

//--- impl ZoneStore

impl ZoneStore for ZoneApex {
    fn class(&self) -> Class {
        self.class
    }

    fn apex_name(&self) -> &StoredName {
        &self.apex_name
    }

    fn read(self: Arc<Self>) -> Box<dyn ReadableZone> {
        let (version, marker) = self.versions().read().current().clone();
        Box::new(ReadZone::new(self, version, marker))
    }

    fn write(
        self: Arc<Self>,
    ) -> Pin<
        Box<
            (dyn Future<Output = Box<(dyn WritableZone + 'static)>>
                 + Send
                 + Sync
                 + 'static),
        >,
    > {
        Box::pin(async move {
            let lock = self.update_lock.clone().lock_owned().await;
            let version = self.versions().read().current().0.next();
            let zone_versions = self.versions.clone();
            Box::new(WriteZone::new(self, lock, version, zone_versions))
                as Box<dyn WritableZone>
        })
    }
}

//--- impl From<&'a ZoneApex>

impl<'a> From<&'a ZoneApex> for CnameError {
    fn from(_: &'a ZoneApex) -> CnameError {
        CnameError::CnameAtApex
    }
}

//--- impl From<&'a ZoneApex>

impl<'a> From<&'a ZoneApex> for ZoneCutError {
    fn from(_: &'a ZoneApex) -> ZoneCutError {
        ZoneCutError::ZoneCutAtApex
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

    pub fn remove_all(&self, version: Version) {
        self.rrsets.remove_all(version);
        self.special.write().remove(version);
        self.children.remove_all(version);
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

    pub fn remove_all(&self, version: Version) {
        self.rrsets
            .write()
            .values_mut()
            .for_each(|rrset| rrset.remove(version));
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
        self.rrsets.remove(version)
    }

    pub fn rollback(&mut self, version: Version) {
        self.rrsets.rollback(version);
    }

    #[allow(dead_code)]
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

    /// Executes a closure for a child, creating a new child if necessary.
    ///
    /// The closure receives a reference to the node and a boolean expressing
    /// whether the child was created.
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

    fn remove_all(&self, version: Version) {
        self.children
            .read()
            .values()
            .for_each(|item| item.remove_all(version))
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
