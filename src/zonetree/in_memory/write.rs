//! Write access to in-memory zones.

use core::future::ready;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::vec::Vec;
use std::{fmt, io};

use futures_util::future::Either;
use parking_lot::RwLock;
use tokio::sync::OwnedMutexGuard;
use tracing::{trace, warn};

use crate::base::iana::Rtype;
use crate::base::name::Label;
use crate::base::{NameBuilder, Serial};
use crate::rdata::ZoneRecordData;
use crate::zonetree::types::{
    InMemoryZoneDiff, InMemoryZoneDiffBuilder, ZoneCut,
};
use crate::zonetree::StoredName;
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

    fn bump_soa_serial(&mut self, old_soa_rr: &Option<SharedRr>) {
        let old_soa_rr = old_soa_rr.as_ref().unwrap();
        let ZoneRecordData::Soa(old_soa) = old_soa_rr.data() else {
            unreachable!()
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
    }

    fn add_soa_remove_diff_entry(
        &mut self,
        old_soa_rr: Option<SharedRr>,
        diff: &mut InMemoryZoneDiffBuilder,
    ) -> Option<Serial> {
        if let Some(old_soa_rr) = old_soa_rr {
            let ZoneRecordData::Soa(old_soa) = old_soa_rr.data() else {
                unreachable!()
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
                unreachable!()
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
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Open error: {err}"),
                )
            });

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
            self.bump_soa_serial(&old_soa_rr);
            new_soa_rr = self.apex.get_soa(self.new_version);
        }

        // Extract (and finish) the created diff, if any.
        let diff = self.diff.lock().unwrap().take();

        if diff.is_some() && new_soa_rr.is_some() {
            let diff = diff.unwrap();
            let diff = arc_into_inner(diff).unwrap();
            let mut diff = Mutex::into_inner(diff).unwrap();

            // Generate a diff entry for the update of the SOA record
            let old_serial =
                self.add_soa_remove_diff_entry(old_soa_rr, &mut diff);

            let new_serial =
                self.add_soa_add_diff_entry(new_soa_rr, &mut diff);

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
    // From: https://doc.rust-lang.org/std/sync/struct.Arc.html#method.into_inner
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
    diff: Option<(StoredName, Arc<Mutex<InMemoryZoneDiffBuilder>>)>,
}

impl WriteNode {
    fn new_apex(
        zone: WriteZone,
        create_diff: bool,
    ) -> Result<Self, io::Error> {
        let apex = zone.apex.clone();

        let diff = if create_diff {
            Some((
                zone.apex.name().clone(),
                Arc::new(Mutex::new(InMemoryZoneDiffBuilder::new())),
            ))
        } else {
            None
        };

        Ok(WriteNode {
            zone,
            node: Either::Left(apex),
            diff,
        })
    }

    fn update_child(&self, label: &Label) -> Result<WriteNode, io::Error> {
        let children = match self.node {
            Either::Left(ref apex) => apex.children(),
            Either::Right(ref node) => node.children(),
        };

        let (node, created) = children
            .with_or_default(label, |node, created| (node.clone(), created));

        let diff = self.diff.as_ref().map(|(owner, diff)| {
            let mut builder = NameBuilder::new_bytes();
            builder.append_label(label.as_slice()).unwrap();
            let new_owner = builder.append_origin(&owner).unwrap();
            (new_owner, diff.clone())
        });

        let node = WriteNode {
            zone: self.zone.clone(),
            node: Either::Right(node),
            diff,
        };

        if created {
            node.make_regular()?;
        }

        Ok(node)
    }

    fn update_rrset(&self, new_rrset: SharedRrset) -> Result<(), io::Error> {
        let rrsets = match self.node {
            Either::Left(ref apex) => apex.rrsets(),
            Either::Right(ref node) => node.rrsets(),
        };

        trace!("Updating RRset");
        if let Some((owner, diff)) = &self.diff {
            let current_rrset = if let Some(current_rrset) = rrsets
                .get(new_rrset.rtype(), self.zone.last_published_version())
            {
                let changed = new_rrset != current_rrset;

                if changed && !current_rrset.is_empty() {
                    Some(current_rrset)
                } else {
                    None
                }
            } else {
                None
            };

            match (current_rrset.is_some(), !new_rrset.is_empty()) {
                (true, true) => {
                    trace!("Diff detected: update of existing RRSET - recording change of RRSET from {current_rrset:?} to {new_rrset:#?}");

                    // Check each resource record in the RRset being updated
                    // to see if it is missing from the new RRSet.
                    let new_rrs = new_rrset.as_rrset().data();
                    let mut removed_rrs =
                        Rrset::new(new_rrset.rtype(), new_rrset.ttl());
                    for removed_rr in current_rrset
                        .as_ref()
                        .unwrap()
                        .as_rrset()
                        .data()
                        .iter()
                        .filter(|rr| !new_rrs.contains(rr))
                    {
                        removed_rrs.push_data(removed_rr.clone());
                    }

                    if !removed_rrs.is_empty() {
                        diff.lock().unwrap().remove(
                            owner.clone(),
                            new_rrset.rtype(),
                            SharedRrset::new(removed_rrs),
                        );
                    }

                    // Check each resource record in the new RRset to see if
                    // it is missing from the RRset being updated.
                    let old_rrs =
                        current_rrset.as_ref().unwrap().as_rrset().data();
                    let mut added_rrs =
                        Rrset::new(new_rrset.rtype(), new_rrset.ttl());
                    for added_rr in new_rrset
                        .as_rrset()
                        .data()
                        .iter()
                        .filter(|rr| !old_rrs.contains(rr))
                    {
                        added_rrs.push_data(added_rr.clone());
                    }

                    if !added_rrs.is_empty() {
                        diff.lock().unwrap().add(
                            owner.clone(),
                            new_rrset.rtype(),
                            SharedRrset::new(added_rrs),
                        );
                    }
                }
                (true, false) => {
                    trace!("Diff detected: update of existing RRSET - recording removal of the current RRSET {current_rrset:#?}");
                    diff.lock().unwrap().remove(
                        owner.clone(),
                        new_rrset.rtype(),
                        current_rrset.unwrap().clone(),
                    );
                }
                (false, true) => {
                    trace!("Diff detected: update of existing RRSET - recording addition of new RRSET {new_rrset:#?}");
                    diff.lock().unwrap().add(
                        owner.clone(),
                        new_rrset.rtype(),
                        new_rrset.clone(),
                    );
                }
                (false, false) => {
                    // NOOP
                }
            }
        }

        rrsets.update(new_rrset, self.zone.new_version);
        self.check_nx_domain()?;
        Ok(())
    }

    fn get_rrset(
        &self,
        rtype: Rtype,
    ) -> Result<Option<SharedRrset>, io::Error> {
        let rrsets = match self.node {
            Either::Left(ref apex) => apex.rrsets(),
            Either::Right(ref node) => node.rrsets(),
        };

        Ok(rrsets.get(rtype, self.zone.new_version))
    }

    fn remove_rrset(&self, rtype: Rtype) -> Result<(), io::Error> {
        let rrsets = match self.node {
            Either::Left(ref apex) => apex.rrsets(),
            Either::Right(ref node) => node.rrsets(),
        };

        if let Some((owner, diff)) = &self.diff {
            if let Some(removed) =
                rrsets.get(rtype, self.zone.last_published_version())
            {
                trace!(
                    "Diff detected: removal of existing RRSET: {removed:#?}"
                );
                diff.lock().unwrap().remove(
                    owner.clone(),
                    rtype,
                    removed.clone(),
                );
            }
        }

        rrsets.remove_rtype(rtype, self.zone.new_version);
        self.check_nx_domain()?;

        Ok(())
    }

    fn make_regular(&self) -> Result<(), io::Error> {
        // TODO: Add support for extending the diff, if any..
        if let Either::Right(ref node) = self.node {
            node.update_special(self.zone.new_version, None);
            self.check_nx_domain()?;
        }
        Ok(())
    }

    fn make_zone_cut(&self, cut: ZoneCut) -> Result<(), io::Error> {
        // TODO: Add support for extending the diff, if any..
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
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Write apex error: {err}"),
            )
        })
    }

    fn make_cname(&self, cname: SharedRr) -> Result<(), io::Error> {
        // TODO: Add support for extending the diff, if any..
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
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Write apex error: {err}"),
            )
        })
    }

    fn remove_all(&self) -> Result<(), io::Error> {
        // TODO: Add support for extending the diff, if any.?
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
        // TODO: Add support for extending the diff, if any.?
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
        self.diff
            .as_ref()
            .map(|(_, diff_builder)| diff_builder.clone())
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
            WriteApexError::NotAllowed => io::Error::new(
                io::ErrorKind::Other,
                "operation not allowed at apex",
            ),
            WriteApexError::Io(err) => err,
        }
    }
}

impl fmt::Display for WriteApexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
