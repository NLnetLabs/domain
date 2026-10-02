//! Write access to in-memory zones.

use core::future::ready;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::io;
use std::sync::Mutex;

use futures_util::future::Either;
use parking_lot::RwLock;
use tokio::sync::OwnedMutexGuard;
use tracing::{trace, warn};

use crate::base::iana::Rtype;
use crate::base::name::Label;
use crate::base::{NameBuilder, Serial};
use crate::rdata::ZoneRecordData;
use crate::zonetree::StoredName;
use crate::zonetree::types::{
    InMemoryZoneDiff, InMemoryZoneDiffBuilder, ZoneCut,
};
use crate::zonetree::{Rrset, SharedRr};
use crate::zonetree::{SharedRrset, WritableZone, WritableZoneNode};

use super::nodes::{Special, ZoneApex, ZoneNode};
use super::versioned::{Version, VersionMarker};

//------------ WriteZone -----------------------------------------------------

/// Serialized write operations on in-memory zones with auto-diffing support.
pub struct WriteZone {
    /// The zone to edit.
    apex: Arc<ZoneApex>,

    /// A write lock on the zone.
    ///
    /// This lock is granted by [`ZoneApex::write()`] and held by us until we
    /// are finished. Further calls to [`ZoneApex::write()`] will block until
    /// we are dropped and release the lock.
    ///
    /// [ZoneApex::write()]: ZoneApex::write()
    _lock: Option<OwnedMutexGuard<()>>,

    /// The version number of the new zone version to create.
    ///
    /// This is set initially in [`new()`] and is incremented by [`commit()`]
    /// after the new zone version has been published.
    ///
    /// Note: There is currently no mechanism for controlling the version
    /// number of the next zone version to be published. However, this version
    /// number is for internal use and is not (yet?) constrained to match the
    /// SOA serial in the zone when the zone is published. Users can therefore
    /// use whatever serial incrementing policy they desire as they control
    /// the content of the SOA record in the zone.
    new_version: Version,

    /// The set of versions already published in this zone prior to starting
    /// the write operation.
    published_versions: Arc<RwLock<ZoneVersions>>,

    /// The set of differences accumulated as changes are made to the zone.
    ///
    /// The outermost Arc<Mutex<Option<..>>> is needed so that [`open()`] can
    /// store a [`ZoneDiffBuilder`] created by [`WriteNode`] and because
    /// [`open()`] takes &self it cannot mutate itself and store it that way.
    /// It also can't just store a reference to [`ZoneDiffBuilder`] as it
    /// needs to call [`ZoneDiffBuilder::build()`] in [`commit()`] which
    /// requires that the builder be consumed (and thus owned, ). It is stored
    /// as an Option because storing a diff is costly thus optional.
    ///
    /// The innermost Arc<Mutex<..>> is needed because each time
    /// [`WriteNode::update_child()`] is called it creates a new [`WriteNode`]
    /// which also needs to be able to add and remove things from the same
    /// diff collection.
    diff: Arc<Mutex<Option<Arc<Mutex<InMemoryZoneDiffBuilder>>>>>,

    /// The zone is dirty if changes have been made but not yet committed.
    ///
    /// This flag is set when a zone is opened for editing, and cleared when
    /// it is committed. If not cleared, on drop any changes made will be
    /// rolled back.
    dirty: Arc<AtomicBool>,
}

impl WriteZone {
    pub(super) fn new(
        apex: Arc<ZoneApex>,
        _lock: OwnedMutexGuard<()>,
        new_version: Version,
        published_versions: Arc<RwLock<ZoneVersions>>,
    ) -> Self {
        WriteZone {
            apex,
            _lock: Some(_lock),
            new_version,
            published_versions,
            diff: Default::default(),
            dirty: Default::default(),
        }
    }

    fn last_published_version(&self) -> Version {
        self.published_versions.read().current().0
    }

    fn bump_soa_serial(
        &mut self,
        old_soa_rr: &Option<SharedRr>,
    ) -> Result<(), io::Error> {
        let Some(old_soa_rr) = old_soa_rr.as_ref() else {
            return Ok(());
        };
        let ZoneRecordData::Soa(old_soa) = old_soa_rr.data() else {
            return Err(io::Error::other(
                "cannot bump SOA in unknown record form",
            ));
        };
        trace!("Commit: old_soa={old_soa:#?}");

        // Create a SOA record with a higher serial number than the previous
        // SOA record.
        let mut new_soa_rrset = Rrset::new(Rtype::SOA, old_soa_rr.ttl());
        let new_soa_serial = old_soa.serial().add(1);
        let new_soa_data = crate::rdata::Soa::new(
            old_soa.mname().clone(),
            old_soa.rname().clone(),
            new_soa_serial,
            old_soa.refresh(),
            old_soa.retry(),
            old_soa.expire(),
            old_soa.minimum(),
        );
        new_soa_rrset.push_data(new_soa_data.into());

        trace!("Commit: new_soa={new_soa_rrset:#?}");
        let new_soa_shared_rrset = SharedRrset::new(new_soa_rrset);

        // Update the SOA record in the new zone version.
        self.apex
            .rrsets()
            .update(new_soa_shared_rrset.clone(), self.new_version);
        Ok(())
    }

    fn add_soa_remove_diff_entry(
        &mut self,
        old_soa_rr: Option<SharedRr>,
        diff: &mut InMemoryZoneDiffBuilder,
    ) -> Option<Serial> {
        if let Some(old_soa_rr) = old_soa_rr {
            let ZoneRecordData::Soa(old_soa) = old_soa_rr.data() else {
                return None;
            };

            let mut removed_soa_rrset =
                Rrset::new(Rtype::SOA, old_soa_rr.ttl());
            removed_soa_rrset.push_data(old_soa_rr.data().clone());
            let removed_soa_rrset = SharedRrset::new(removed_soa_rrset);

            trace!(
                "Diff: recording removal of old SOA: {removed_soa_rrset:#?}"
            );
            diff.remove(
                self.apex.name().clone(),
                Rtype::SOA,
                removed_soa_rrset,
            );

            Some(old_soa.serial())
        } else {
            None
        }
    }

    fn add_soa_add_diff_entry(
        &mut self,
        new_soa_rr: Option<SharedRr>,
        diff: &mut InMemoryZoneDiffBuilder,
    ) -> Option<Serial> {
        if let Some(new_soa_rr) = new_soa_rr {
            let ZoneRecordData::Soa(new_soa) = new_soa_rr.data() else {
                return None;
            };
            let mut new_soa_shared_rrset =
                Rrset::new(Rtype::SOA, new_soa_rr.ttl());
            new_soa_shared_rrset.push_data(new_soa_rr.data().clone());
            let new_soa_rrset = SharedRrset::new(new_soa_shared_rrset);

            trace!("Diff: recording addition of new SOA: {new_soa_rrset:#?}");
            diff.add(self.apex.name().clone(), Rtype::SOA, new_soa_rrset);

            Some(new_soa.serial())
        } else {
            None
        }
    }

    fn publish_new_zone_version(&mut self) {
        trace!(
            "Commit: Making zone version '{:#?}' current",
            self.new_version
        );
        let marker = self
            .published_versions
            .write()
            .update_current(self.new_version);
        self.published_versions
            .write()
            .push_version(self.new_version, marker);

        trace!("Commit: zone versions: {:#?}", self.published_versions);
        trace!("Commit: zone dump:\n{:#?}", self.apex);

        // Start the next version.
        self.new_version = self.new_version.next();

        self.dirty.store(false, Ordering::SeqCst);
    }
}

//--- impl Clone

impl Clone for WriteZone {
    fn clone(&self) -> Self {
        Self {
            apex: self.apex.clone(),
            _lock: None,
            new_version: self.new_version,
            published_versions: self.published_versions.clone(),
            diff: self.diff.clone(),
            dirty: Default::default(),
        }
    }
}

//--- impl Drop

impl Drop for WriteZone {
    fn drop(&mut self) {
        if self.dirty.swap(false, Ordering::SeqCst) {
            self.apex.rollback(self.new_version);
        }
    }
}

//--- impl WritableZone

impl WritableZone for WriteZone {
    #[allow(clippy::type_complexity)]
    fn open(
        &self,
        create_diff: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        let new_apex = WriteNode::new_apex(self.clone(), create_diff);

        if let Ok(write_node) = &new_apex {
            *self.diff.lock().unwrap() = write_node.diff();
            self.dirty.store(true, Ordering::SeqCst);
        }

        let res = new_apex
            .map(|node| Box::new(node) as Box<dyn WritableZoneNode>)
            .map_err(|err| io::Error::other(format!("Open error: {err}")));

        Box::pin(ready(res))
    }

    /// Publish in-progress zone edits.
    ///
    /// If `bump_soa_serial` is true AND the zone has an existing SOA record
    /// AND the to-be-published zone version does NOT have a new SOA record,
    /// then a copy of the old SOA record with its serial number increased
    /// will be saved.
    ///
    /// If a diff has been captured, also ensure that it contains diff entries
    /// for removing the old SOA and adding the new SOA.
    fn commit(
        &mut self,
        bump_soa_serial: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<InMemoryZoneDiff>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        let mut out_diff = None;

        // If bump_soa_serial is true AND if the zone already had a SOA record
        // AND no SOA record exists in the new version of the zone: add a SOA
        // record with a higher serial than the previous SOA record.
        //
        // For an empty zone being populated by AXFR this won't be possible as
        // there won't be an existing SOA to increment, but there should in
        // that case be a SOA record in the new version of the zone anyway.

        let old_soa_rr = self.apex.get_soa(self.last_published_version());
        let mut new_soa_rr = self.apex.get_soa(self.new_version);

        if bump_soa_serial
            && old_soa_rr.is_some()
            && (new_soa_rr.is_none() || new_soa_rr == old_soa_rr)
        {
            if let Err(err) = self.bump_soa_serial(&old_soa_rr) {
                return Box::pin(ready(Err(err)));
            }
            new_soa_rr = self.apex.get_soa(self.new_version);
        }

        // Extract (and finish) the created diff, if any.
        let diff = self.diff.lock().unwrap().take();

        if let Some((diff, new_soa_rr)) = diff.zip(new_soa_rr) {
            let diff = arc_into_inner(diff).unwrap();
            let mut diff = Mutex::into_inner(diff).unwrap();

            // Generate a diff entry for the update of the SOA record
            let old_serial =
                self.add_soa_remove_diff_entry(old_soa_rr, &mut diff);

            let new_serial =
                self.add_soa_add_diff_entry(Some(new_soa_rr), &mut diff);

            if old_serial.is_some() && new_serial.is_some() {
                out_diff = match diff.build() {
                    Ok(zone_diff) => Some(zone_diff),
                    Err(err) => {
                        warn!("Error constructing diff: {err}");
                        None
                    }
                };
            }
        }

        self.publish_new_zone_version();

        Box::pin(ready(Ok(out_diff)))
    }
}

/// Returns the inner value, if the Arc has exactly one strong reference.
///
/// Wrapper around [`Arc::into_inner()`] with an implementation back-ported
/// for Rust <1.70.0 when [`Arc::into_inner()`] did not exist yet.
#[rustversion::since(1.70.0)]
fn arc_into_inner<T>(this: Arc<Mutex<T>>) -> Option<Mutex<T>> {
    #[allow(clippy::incompatible_msrv)]
    Arc::into_inner(this)
}

/// Returns the inner value, if the Arc has exactly one strong reference.
///
/// Wrapper around [`Arc::into_inner()`] with an implementation back-ported
/// for Rust <1.70.0 when [`Arc::into_inner()`] did not exist yet.
#[rustversion::before(1.70.0)]
fn arc_into_inner<T>(this: Arc<Mutex<T>>) -> Option<Mutex<T>> {
    // From: https://doc.rust-lang.org/alloc/sync/struct.Arc.html#method.into_inner
    //
    // "If Arc::into_inner is called on every clone of this Arc, it is
    // guaranteed that exactly one of the calls returns the inner value. This
    // means in particular that the inner value is not dropped.
    //
    // Arc::try_unwrap is conceptually similar to Arc::into_inner, but it is
    // meant for different use-cases. If used as a direct replacement for
    // Arc::into_inner anyway, such as with the expression
    // Arc::try_unwrap(this).ok(), then it does not give the same guarantee as
    // described in the previous paragraph. For more information, see the
    // examples below and read the documentation of Arc::try_unwrap."
    //
    // In our case there is no other thread trying to unwrap the value.
    Arc::try_unwrap(this).ok()
}

//------------ WriteNode ------------------------------------------------------

/// Write operations on in-memory zone tree nodes with auto-diffing support.
pub struct WriteNode {
    /// The writer for the zone we are working with.
    zone: WriteZone,

    /// The node we are updating.
    node: Either<Arc<ZoneApex>, Arc<ZoneNode>>,

    /// The diff we are building, if enabled.
    diff: Option<Arc<Mutex<InMemoryZoneDiffBuilder>>>,

    /// The owner name of the current node.
    owner: StoredName,
}

impl WriteNode {
    fn new_apex(
        zone: WriteZone,
        create_diff: bool,
    ) -> Result<Self, io::Error> {
        let apex = zone.apex.clone();

        let diff = if create_diff {
            Some(Arc::new(Mutex::new(InMemoryZoneDiffBuilder::new())))
        } else {
            None
        };

        let owner = zone.apex.name().clone();
        Ok(WriteNode {
            zone,
            node: Either::Left(apex),
            diff,
            owner,
        })
    }

    fn update_child(&self, label: &Label) -> Result<WriteNode, io::Error> {
        let children = match self.node {
            Either::Left(ref apex) => apex.children(),
            Either::Right(ref node) => node.children(),
        };

        let (node, created) = children
            .with_or_default(label, |node, created| (node.clone(), created));

        let mut builder = NameBuilder::new_bytes();
        builder.append_label(label.as_slice()).unwrap();
        let owner = builder.append_origin(&self.owner).unwrap();

        let node = WriteNode {
            zone: self.zone.clone(),
            node: Either::Right(node),
            diff: self.diff.clone(),
            owner,
        };

        if created {
            node.make_regular()?;
        }

        Ok(node)
    }

    fn update_rrset(&self, new_rrset: SharedRrset) -> Result<(), io::Error> {
        trace!("Updating RRset");

        let rtype = new_rrset.rtype();
        let rrset_before = self.get_rrset(rtype)?;

        match self.node {
            Either::Right(ref node) => {
                if !self.update_rrset_special(&new_rrset, node)? {
                    node.rrsets().update(new_rrset, self.zone.new_version);
                }
            }
            Either::Left(ref apex) => {
                apex.rrsets().update(new_rrset, self.zone.new_version);
            }
        }

        self.check_nx_domain()?;

        let rrset_after = self.get_rrset(rtype)?;
        self.update_rrsets_diff(rrset_before, rrset_after);

        Ok(())
    }

    /// Update the diff as if the given RRSET is applied to the given set
    /// diff.
    fn update_rrsets_diff(
        &self,
        before: Option<SharedRrset>,
        after: Option<SharedRrset>,
    ) {
        std::dbg!(&before);
        std::dbg!(&after);
        let Some(diff) = &self.diff else { return };

        let mut added: Option<SharedRrset> = None;
        let mut removed: Option<SharedRrset> = None;

        match (&before, &after) {
            (None, None) => { /* Nothing to do */ }
            (None, Some(_)) => added = after,
            (Some(_), None) => removed = before,
            (Some(before), Some(after)) => {
                // Check each resource record in the RRset being updated
                // to see if it is missing from the new RRSet.
                let mut removed_rrs =
                    Rrset::new(before.rtype(), before.ttl());
                for removed_rr in before
                    .data()
                    .iter()
                    .filter(|&rr| !after.data().contains(rr))
                {
                    removed_rrs.push_data(removed_rr.clone());
                }
                if !removed_rrs.is_empty() {
                    removed = Some(SharedRrset::new(removed_rrs));
                }

                // Check each resource record in the new RRset to see if
                // it is missing from the RRset being updated.
                let mut added_rrs = Rrset::new(after.rtype(), after.ttl());
                for added_rr in after
                    .data()
                    .iter()
                    .filter(|&rr| !before.data().contains(rr))
                {
                    added_rrs.push_data(added_rr.clone());
                }
                if !added_rrs.is_empty() {
                    added = Some(SharedRrset::new(added_rrs));
                }
            }
        }

        let mut locked = diff.lock().unwrap();
        if let Some(removed) = removed {
            locked.remove(self.owner.clone(), removed.rtype(), removed);
        }
        if let Some(added) = added {
            locked.add(self.owner.clone(), added.rtype(), added);
        }
    }

    /// Apply an RRSET update to the "special" if applicable.
    ///
    /// Returns true when the special was applied and the caller should not
    /// attempt to further apply the update, false otherwise.
    fn update_rrset_special(
        &self,
        new_rrset: &SharedRrset,
        node: &Arc<ZoneNode>,
    ) -> Result<bool, io::Error> {
        match new_rrset.rtype() {
            Rtype::NS => {
                // Keep any existing DS or Glue at the zone cut as this update
                // should only affect the NS RRs, not other RRs.
                let possible_cut = node.zone_cut(self.zone.new_version);

                // Also convert any plain DS record existed that was not
                // yet able to be stored in a ZoneCut as the accompanying NS
                // record was missing.
                let existing_ds =
                    node.rrsets().get(Rtype::DS, self.zone.new_version);
                node.rrsets().remove_rtype(Rtype::DS, self.zone.new_version);

                let cut = match possible_cut {
                    Some(mut cut) => {
                        // There shouldn't have been a DS RRSET in the
                        // separate RRSET collection if there is an existing
                        // zone cut as the attempt to insert a DS should have
                        // caused it to be added into the existing zone cut at
                        // that time. We don't know how to merge any existing
                        // separate DS RRSET with any DS RRSET that is already
                        // part of the existing zone cut so we don't try and
                        // handle this case that shouldn't happen.
                        if existing_ds.is_some() && cut.ds.is_some() {
                            return Err(io::Error::other(
                                "Cannot update zone cut because DS RRSET exists both in the existing cut and in the free RRSET collection",
                            ));
                        }

                        // Replace the existing NS RRSET with the new one.
                        cut.ns = new_rrset.clone();
                        cut
                    }
                    None => {
                        // Create a new zone cut combining the given NS RRSET
                        // and any existing DS RRSET.
                        ZoneCut {
                            name: self.owner.clone(),
                            ns: new_rrset.clone(),
                            ds: existing_ds,
                            glue: vec![],
                        }
                    }
                };

                self.make_zone_cut(cut)?;
                return Ok(true);
            }
            Rtype::DS => {
                if let Some(mut cut) = node.zone_cut(self.zone.new_version) {
                    cut.ds = Some(new_rrset.clone());
                    self.make_zone_cut(cut)?;
                    return Ok(true);
                } else {
                    // A naked DS without NS cannot be represented by a
                    // "special" zone cut, proceed to the plain RRSET update
                    // mechanism.
                }
            }
            Rtype::CNAME => {
                if new_rrset.data().len() != 1 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let cname = SharedRr::new(
                    new_rrset.ttl(),
                    new_rrset.data()[0].clone(),
                );
                self.make_cname(cname)?;
                return Ok(true);
            }
            _ => {
                // This RTYPE is not stored in a "special", proceed to the
                // plain RRSET update mechanism.
            }
        }

        Ok(false)
    }

    fn get_rrset(
        &self,
        rtype: Rtype,
    ) -> Result<Option<SharedRrset>, io::Error> {
        let rrsets = match self.node {
            Either::Left(ref apex) => apex.rrsets(),
            Either::Right(ref node) => {
                // Emulate storing of "special" records as RRsets because
                // the WritableZone interface we are implementing offers an
                // RRset based interface to the caller which means that the
                // caller has no way to obtain records that are represented as
                // "specials" (as these are an internal implementation detail
                // of the in-memory zone tree) and so we have to expose any
                // records we store, regardless of whether stored as an RRset
                // or as a "special", as RRsets.
                if matches!(rtype, Rtype::CNAME | Rtype::NS | Rtype::DS) {
                    return Ok(node.with_special(
                        self.zone.new_version,
                        |special| {
                            special.and_then(|special| match special {
                                Special::Cname(rr)
                                    if rtype == Rtype::CNAME =>
                                {
                                    let mut rrset =
                                        Rrset::new(rr.rtype(), rr.ttl());
                                    rrset.push_data(rr.data().clone());
                                    Some(SharedRrset::new(rrset))
                                }
                                Special::Cut(cut) if rtype == Rtype::NS => {
                                    Some(cut.ns.clone())
                                }
                                Special::Cut(cut) if rtype == Rtype::DS => {
                                    cut.ds.clone()
                                }
                                _ => None,
                            })
                        },
                    ));
                }
                node.rrsets()
            }
        };

        Ok(rrsets.get(rtype, self.zone.new_version))
    }

    fn remove_rrset(&self, rtype: Rtype) -> Result<(), io::Error> {
        let rrsets = match self.node {
            Either::Left(ref apex) => apex.rrsets(),
            Either::Right(ref node) => node.rrsets(),
        };

        if let Some(diff) = &self.diff {
            if let Some(removed) =
                rrsets.get(rtype, self.zone.last_published_version())
            {
                trace!(
                    "Diff detected: removal of existing RRSET: {removed:#?}"
                );
                diff.lock().unwrap().remove(
                    self.owner.clone(),
                    rtype,
                    removed.clone(),
                );
            }
        }

        rrsets.remove_rtype(rtype, self.zone.new_version);

        if let Either::Right(ref node) = self.node {
            let update =
                node.with_special(self.zone.new_version, |special| {
                    if let Some(special) = special {
                        match special {
                            Special::Cut(zone_cut)
                                if rtype == Rtype::DS
                                    && zone_cut.ds.is_some() =>
                            {
                                // The caller is removing a DS record and
                                // the node special represents a zone cut. We
                                // have to remove the DS from the zone cut but
                                // otherwise preserve it.
                                let mut updated_zone_cut = zone_cut.clone();
                                updated_zone_cut.ds = None;
                                Some(Some(Special::Cut(updated_zone_cut)))
                            }
                            Special::Cut(_) if rtype == Rtype::NS => {
                                // The caller is removing an NS record and the
                                // node special represents a zone cut so we
                                // need to remove the special by setting it
                                // to None.
                                Some(None)
                            }
                            Special::Cname(_) if rtype == Rtype::CNAME => {
                                // The caller is removing a CNAME record and
                                // the node special represents a CNAME so we
                                // need to remove the special by setting it
                                // to None.
                                Some(None)
                            }
                            _ => None,
                        }
                    } else {
                        None
                    }
                });

            if let Some(updated_special) = update {
                node.update_special(self.zone.new_version, updated_special);
            }
        }

        // If we removed the last RRSET make sure that this entire node is
        // reported as non-existent.
        self.check_nx_domain()?;

        Ok(())
    }

    fn make_regular(&self) -> Result<(), io::Error> {
        if let Either::Right(ref node) = self.node {
            node.update_special(self.zone.new_version, None);
            self.check_nx_domain()?;
        }
        Ok(())
    }

    fn make_zone_cut(&self, cut: ZoneCut) -> Result<(), io::Error> {
        match self.node {
            Either::Left(_) => Err(WriteApexError::NotAllowed),
            Either::Right(ref node) => {
                node.update_special(
                    self.zone.new_version,
                    Some(Special::Cut(cut)),
                );
                Ok(())
            }
        }
        .map_err(|err| io::Error::other(format!("Write apex error: {err}")))
    }

    fn make_cname(&self, cname: SharedRr) -> Result<(), io::Error> {
        match self.node {
            Either::Left(_) => Err(WriteApexError::NotAllowed),
            Either::Right(ref node) => {
                node.update_special(
                    self.zone.new_version,
                    Some(Special::Cname(cname)),
                );
                Ok(())
            }
        }
        .map_err(|err| io::Error::other(format!("Write apex error: {err}")))
    }

    fn remove_all(&self) -> Result<(), io::Error> {
        match self.node {
            Either::Left(ref apex) => {
                apex.remove_all(self.zone.new_version);
            }
            Either::Right(ref node) => {
                node.remove_all(self.zone.new_version);
            }
        }

        Ok(())
    }

    /// Makes sure a NXDomain special is set or removed as necesssary.
    fn check_nx_domain(&self) -> Result<(), io::Error> {
        let node = match self.node {
            Either::Left(_) => return Ok(()),
            Either::Right(ref node) => node,
        };
        let opt_new_nxdomain = node.with_special(
            self.zone.new_version,
            |special| match special {
                Some(Special::NxDomain) => {
                    if !node.rrsets().is_empty(self.zone.new_version) {
                        Some(false)
                    } else {
                        None
                    }
                }
                None => {
                    if node.rrsets().is_empty(self.zone.new_version) {
                        Some(true)
                    } else {
                        None
                    }
                }
                _ => None,
            },
        );
        if let Some(new_nxdomain) = opt_new_nxdomain {
            if new_nxdomain {
                node.update_special(
                    self.zone.new_version,
                    Some(Special::NxDomain),
                );
            } else {
                node.update_special(self.zone.new_version, None);
            }
        }
        Ok(())
    }

    fn diff(&self) -> Option<Arc<Mutex<InMemoryZoneDiffBuilder>>> {
        self.diff.clone()
    }
}

//--- impl WritableZoneNode

impl WritableZoneNode for WriteNode {
    #[allow(clippy::type_complexity)]
    fn update_child(
        &self,
        label: &Label,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        let node = self
            .update_child(label)
            .map(|node| Box::new(node) as Box<dyn WritableZoneNode>);
        Box::pin(ready(node))
    }

    fn update_rrset(
        &self,
        rrset: SharedRrset,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.update_rrset(rrset)))
    }

    fn get_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<SharedRrset>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        Box::pin(ready(self.get_rrset(rtype)))
    }

    fn remove_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.remove_rrset(rtype)))
    }

    fn make_regular(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.make_regular()))
    }

    fn make_zone_cut(
        &self,
        cut: ZoneCut,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.make_zone_cut(cut)))
    }

    fn make_cname(
        &self,
        cname: SharedRr,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.make_cname(cname)))
    }

    fn remove_all(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.remove_all()))
    }
}

//------------ WriteApexError ------------------------------------------------

/// The requested operation is not allowed at the apex of a zone.
#[derive(Debug)]
pub enum WriteApexError {
    /// This operation is not allowed at the apex.
    NotAllowed,

    /// An IO error happened while processing the operation.
    Io(io::Error),
}

impl From<io::Error> for WriteApexError {
    fn from(src: io::Error) -> WriteApexError {
        WriteApexError::Io(src)
    }
}

impl From<WriteApexError> for io::Error {
    fn from(src: WriteApexError) -> io::Error {
        match src {
            WriteApexError::NotAllowed => {
                io::Error::other("operation not allowed at apex")
            }
            WriteApexError::Io(err) => err,
        }
    }
}

impl fmt::Display for WriteApexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            WriteApexError::NotAllowed => {
                f.write_str("operation not allowed")
            }
            WriteApexError::Io(ref err) => err.fmt(f),
        }
    }
}

//------------ ZoneVersions --------------------------------------------------

/// An ordered collection of zone versions of which only one is "current".
#[derive(Debug)]
pub struct ZoneVersions {
    current: (Version, Arc<VersionMarker>),
    all: Vec<(Version, Weak<VersionMarker>)>,
}

impl ZoneVersions {
    pub fn update_current(&mut self, version: Version) -> Arc<VersionMarker> {
        let marker = Arc::new(VersionMarker);
        trace!(
            "Changing current zone version from {:?} to {version:?}",
            self.current
        );
        self.current = (version, marker.clone());
        marker
    }

    pub fn push_version(
        &mut self,
        version: Version,
        marker: Arc<VersionMarker>,
    ) {
        trace!("Pushing new zone version {version:?}");
        self.all.push((version, Arc::downgrade(&marker)))
    }

    pub fn clean_versions(&mut self) -> Option<Version> {
        let mut max_version = None;
        self.all.retain(|item| {
            if item.1.strong_count() > 0 {
                true
            } else {
                match max_version {
                    Some(old) => {
                        if item.0 > old {
                            max_version = Some(item.0)
                        }
                    }
                    None => max_version = Some(item.0),
                }
                false
            }
        });
        max_version
    }

    pub fn current(&self) -> &(Version, Arc<VersionMarker>) {
        &self.current
    }
}

impl Default for ZoneVersions {
    fn default() -> Self {
        let marker = Arc::new(VersionMarker);
        let weak_marker = Arc::downgrade(&marker);
        ZoneVersions {
            current: (Version::default(), marker),
            all: vec![(Version::default(), weak_marker)],
        }
    }
}
