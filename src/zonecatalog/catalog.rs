use core::fmt::Debug;
/// Note to self: This design ties XFR and catalogs together, but really they
/// are separate things. Maybe better have triggers/callbacks or something for
/// joining separate pieces together, including the XFR-in
/// XfrMiddlewareService functionality?
// TODO: Add IXFR diff purging.
// TODO: Add IXFR diff condensation.
use core::net::{IpAddr, SocketAddr};

use core::time::Duration;
use std::borrow::Cow;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{BTreeMap, HashMap};
use std::string::String;
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use bytes::Bytes;
use futures::stream::FuturesUnordered;
use tokio::net::TcpStream;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, info, trace, warn};

use crate::base::iana::Class;
use crate::base::name::{Label, ToLabelIter};
use crate::base::{
    CanonicalOrd, MessageBuilder, Name, Rtype, Serial, ToName, Ttl,
};
use crate::net::client::protocol::UdpConnect;
use crate::net::client::request::{RequestMessage, SendRequest};
use crate::net::client::{dgram, stream};
use crate::rdata::{
    AllRecordData, Cname, Dname, Mb, Md, Mf, Mg, Mx, Ns, Nsec, Ptr, Soa,
    ZoneRecordData,
};
use crate::zonetree::error::{OutOfZone, ZoneTreeModificationError};
use crate::zonetree::{
    AnswerContent, ReadableZone, Rrset, SharedRrset, StoredName,
    WritableZone, WritableZoneNode, Zone, ZoneDiff, ZoneStore, ZoneTree,
};
use core::any::Any;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use futures::future::Map;
use futures::FutureExt;
use std::boxed::Box;
use std::future::Future;
use std::io;
use std::vec::Vec;
use tokio::sync::Mutex;
use tokio::time::{sleep_until, Instant, Sleep};
use tokio_stream::StreamExt;

//------------ Constants -----------------------------------------------------

const DEF_PRIMARY_PORT: u16 = 53;
const MIN_DURATION_BETWEEN_ZONE_REFRESHES: tokio::time::Duration =
    tokio::time::Duration::new(60, 0);

//------------ Acl -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AclEntry {
    _key_name: Option<String>,
    port: Option<u16>,
}

#[derive(Clone, Debug, Default)]
pub struct Acl {
    entries: HashMap<IpAddr, AclEntry>,
}

impl Acl {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Deref for Acl {
    type Target = HashMap<IpAddr, AclEntry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

//------------ XfrMode -------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub enum XfrMode {
    #[default]
    None,
    AxfrOnly,
    AxfrAndIxfr,
}

//------------ IxfrMode ------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub enum IxfrMode {
    #[default]
    None,
    Udp,
    Tcp,
}

//------------ TlsMode -------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub enum TlsMode {
    #[default]
    None,
    Authenticated(String),
}

//------------ PrimaryInfo ---------------------------------------------------

/// Information about the primary server that owns a zone.
#[derive(Clone, Debug)]
pub struct PrimaryInfo {
    pub addr: SocketAddr,
    pub xfr_mode: XfrMode,
    pub ixfr_mode: IxfrMode,
    pub tls_mode: TlsMode,
}

impl PrimaryInfo {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            xfr_mode: Default::default(),
            ixfr_mode: Default::default(),
            tls_mode: Default::default(),
        }
    }
}

//------------ ZoneType ------------------------------------------------------

#[derive(Clone, Debug)]
pub enum ZoneType {
    /// We are primary for the zone and allow the specified clients to request
    /// the zone via XFR.
    Primary(Acl),

    /// We are secondary for the zone and will request the zone via XFR from
    /// the specified primary, and allow the specified (primary?) servers to
    /// notify us of an update to the zone.
    Secondary(PrimaryInfo, Acl),
}

//------------ ZoneDiffKey ---------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ZoneDiffKey {
    start_serial: Serial,
    end_serial: Serial,
}

impl Ord for ZoneDiffKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.start_serial.canonical_cmp(&other.start_serial)
    }
}

impl PartialOrd for ZoneDiffKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ZoneDiffKey {
    pub fn new(start_serial: Serial, end_serial: Serial) -> Self {
        Self {
            start_serial,
            end_serial,
        }
    }

    pub fn start_serial(&self) -> Serial {
        self.start_serial
    }

    pub fn to_serial(&self) -> Serial {
        self.end_serial
    }
}

//------------ ZoneDiffs -----------------------------------------------------

pub type ZoneDiffs = BTreeMap<ZoneDiffKey, Arc<ZoneDiff>>;

//------------ Timers --------------------------------------------------------

#[derive(Debug)]
pub struct Timers {
    refresh: Ttl,
    // None means never refreshed
    last_refreshed: Arc<std::sync::Mutex<Option<Instant>>>,
    retry: Ttl,
    expire: Ttl,
}

impl Timers {
    pub fn new(soa: &Soa<Name<Bytes>>) -> Self {
        let last_refreshed = Arc::new(std::sync::Mutex::new(None));
        Timers {
            refresh: soa.refresh(),
            last_refreshed,
            retry: soa.retry(),
            expire: soa.expire(),
        }
    }
}

//------------ TimerInfo -----------------------------------------------------

#[derive(Clone, Debug)]
struct TimerInfo {
    key: (StoredName, Class),
    end_instant: Instant,
}
impl TimerInfo {
    fn new(key: (Name<Bytes>, Class), refresh: Ttl) -> Self {
        trace!(
            "Creating TimerInfo for zone {} with refresh duration {} seconds",
            key.0,
            refresh.into_duration().as_secs()
        );
        let end_instant =
            Instant::now().checked_add(refresh.into_duration()).unwrap();
        Self { key, end_instant }
    }
}

//------------ TimerInfoFuture -----------------------------------------------

struct TimerInfoFuture {
    timer_info: TimerInfo,
    sleep_fut: Pin<Box<Sleep>>,
}
impl TimerInfoFuture {
    fn new(timer_info: TimerInfo) -> Self {
        let sleep_fut = Box::pin(sleep_until(timer_info.end_instant));
        Self {
            timer_info,
            sleep_fut,
        }
    }
}

impl Future for TimerInfoFuture {
    type Output = TimerInfo;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        match self.sleep_fut.poll_unpin(cx) {
            Poll::Ready(()) => Poll::Ready(self.timer_info.clone()),
            Poll::Pending => Poll::Pending,
        }
    }
}

//------------ ZoneInfo ------------------------------------------------------

#[derive(Debug)]
pub struct ZoneInfo {
    _catalog_member_id: Option<StoredName>,
    zone_type: ZoneType,
    diffs: Arc<Mutex<ZoneDiffs>>,
}

impl ZoneInfo {
    pub async fn add_diff(&self, diff: ZoneDiff) {
        let k = ZoneDiffKey::new(
            diff.start_serial.unwrap(), // SAFETY: TODO
            diff.end_serial.unwrap(),   // SAFETY: TODO
        );
        self.diffs.lock().await.insert(k, Arc::new(diff));
    }

    /// Inclusive (i.e. start_serial..=end_serial).
    pub async fn diffs_for_range(
        &self,
        start_serial: Serial,
        end_serial: Serial,
    ) -> Vec<Arc<ZoneDiff>> {
        let mut out_diffs = Vec::new();
        let mut serial = start_serial;

        let diffs = self.diffs.lock().await;

        // TODO: Should we call partial_cmp() instead of < and > and handle
        // the None case specially?

        // TODO: Does this handle serial range wrap around correctly?

        // Note: Assumes diffs are ordered by rising start serial.
        for (key, diff) in diffs.iter() {
            if key.start_serial() < serial {
                // Diff is for a serial that is too old, skip it.
                continue;
            } else if key.start_serial() > serial
                || key.start_serial() > end_serial
            {
                // Diff is for a serial that is too new, abort as we don't
                // have the diff that the client needs.
                return vec![];
            } else if key.start_serial() == end_serial {
                // We found the last diff that the client needs.
                break;
            }

            out_diffs.push(diff.clone());
            serial = key.to_serial();
        }

        out_diffs
    }
}

//------------ NotifyMsg -----------------------------------------------------

#[derive(Debug)]
struct ZoneChangedMsg {
    class: Class,
    apex_name: StoredName,

    // The RFC 1996 section 3.11 known master that was the source of the
    // NOTIFY, if the zone change was learned via an RFC 1996 NOTIFY query.
    source: Option<IpAddr>,
}

//------------ Catalog -------------------------------------------------------

/// A set of zones that are kept in sync with other servers.
///
/// Also capable of acting as an RFC 9432 Catalog Zone producer/consumer.
#[derive(Debug)]
pub struct Catalog {
    // cat_zone: Zone, // TODO
    member_zones: Arc<ArcSwap<ZoneTree>>,
    loaded_arc: RwLock<Arc<ZoneTree>>,
    notify_rx: tokio::sync::Mutex<Receiver<ZoneChangedMsg>>,
    notify_tx: Sender<ZoneChangedMsg>,
    running: AtomicBool,
}

impl Catalog {
    pub fn new() -> Result<Self, ZoneTreeModificationError> {
        Self::new_with_zones(ZoneTree::new())
    }

    /// Construct a catalog from a [`ZoneTree`].
    pub fn new_with_zones(
        zones: ZoneTree,
    ) -> Result<Self, ZoneTreeModificationError> {
        // TODO: Maintain an RFC 9432 catalog zone
        // let apex_name = Name::from_str("catalog.invalid.").unwrap();
        // let invalid_name = Name::from_str("invalid.").unwrap();
        // let mut cat_zone = ZoneBuilder::new(apex_name.clone(), Class::IN);

        // let mut soa_rrset = Rrset::new(Rtype::SOA, Ttl::from_hours(1));
        // let soa_data = crate::rdata::Soa::new(
        //     invalid_name.clone(),
        //     invalid_name.clone(),
        //     Serial::now(),
        //     Ttl::from_hours(1), // refresh
        //     Ttl::from_hours(1), // retry
        //     Ttl::from_hours(1), // expire
        //     Ttl::from_hours(1), // minimum
        // );
        // soa_rrset.push_data(soa_data.into());
        // let soa_rrset = SharedRrset::new(soa_rrset);
        // cat_zone.insert_rrset(&apex_name, soa_rrset).unwrap();

        // let mut ns_rrset = Rrset::new(Rtype::NS, Ttl::from_hours(1));
        // ns_rrset.push_data(crate::rdata::Ns::new(invalid_name).into());
        // let ns_rrset = SharedRrset::new(ns_rrset);
        // cat_zone.insert_rrset(&apex_name, ns_rrset).unwrap();

        // let mut txt_rrset = Rrset::new(Rtype::TXT, Ttl::from_hours(1));
        // let mut txt_builder = TxtBuilder::<Vec<u8>>::new();
        // let txt = {
        //     let cs = CharStr::<Vec<u8>>::from_str("2").unwrap();
        //     txt_builder.append_charstr(&cs).unwrap();
        //     txt_builder.finish().unwrap()
        // };
        // // txt_rrset.push_data(txt);

        // let cat_zone = cat_zone.build();

        let mut member_zones = ZoneTree::new();
        let (notify_tx, notify_rx) = mpsc::channel(10);
        let zone_type = ZoneType::Primary(Acl::new());

        for zone in zones.iter_zones() {
            let wrapped_zone = Self::wrap_zone(
                zone.clone(),
                zone_type.clone(),
                notify_tx.clone(),
            );
            member_zones.insert_zone(wrapped_zone)?;
        }

        let member_zones = Arc::new(ArcSwap::from_pointee(member_zones));
        let loaded_arc = RwLock::new(member_zones.load_full());
        let notify_rx = tokio::sync::Mutex::new(notify_rx);

        let catalog = Catalog {
            // cat_zone,
            member_zones,
            loaded_arc,
            notify_rx,
            notify_tx,
            running: AtomicBool::new(false),
        };

        Ok(catalog)
    }
}

impl Catalog {
    pub fn insert_zone(
        &self,
        zone: Zone,
        zone_type: ZoneType,
    ) -> Result<(), ZoneTreeModificationError> {
        let mut new_zones = self.zones().deref().clone();
        let wrapped_zone =
            Self::wrap_zone(zone, zone_type, self.notify_tx.clone());
        new_zones.insert_zone(wrapped_zone)?;
        self.member_zones.store(Arc::new(new_zones));
        self.update_lodaded_arc();
        Ok(())
    }

    pub async fn notify_zone_changed(
        &self,
        class: Class,
        apex_name: &StoredName,
        source: Option<IpAddr>,
    ) -> Result<(), CatalogError> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(CatalogError::NotRunning);
        }

        if self.zones().get_zone(apex_name, class).is_none() {
            return Err(CatalogError::UnknownZone);
        };

        // https://datatracker.ietf.org/doc/html/rfc1996#section-2
        //   "2.1. The following definitions are used in this document:
        //    ...
        //    Master          any authoritative server configured to be the
        //                    source of zone transfer for one or more slave
        //                    servers.
        //
        //    Primary Master  master server at the root of the zone transfer
        //                    dependency graph.  The primary master is named
        //                    in the zone's SOA MNAME field and optionally by
        //                    an NS RR. There is by definition only one
        //                    primary master server per zone.
        //
        //    Stealth         like a slave server except not listed in an NS
        //                    RR for the zone.  A stealth server, unless
        //                    explicitly configured to do otherwise, will set
        //                    the AA bit in responses and be capable of acting
        //                    as a master.  A stealth server will only be
        //                    known by other servers if they are given static
        //                    configuration data indicating its existence."

        // https://datatracker.ietf.org/doc/html/rfc1996#section-3
        //   "3.10. If a slave receives a NOTIFY request from a host that is
        //    not a known master for the zone containing the QNAME, it should
        //    ignore the request and produce an error message in its
        //    operations log."

        // From the definition in 2.1 above "known masters" are the combined
        // set of masters and stealth masters. If we are the primary for the
        // zone because this notification arose internally due to a local
        // change in the zone then this check is irrelevant. Comparing the SOA
        // MNAME or NS record value to the source IP address would require
        // resolving the name to an IP address. Such a check would not be
        // quick so we leave that to the running Catalog task to handle.

        let msg = ZoneChangedMsg {
            class,
            apex_name: apex_name.clone(),
            source,
        };

        send_zone_changed_msg(&self.notify_tx, msg)
            .await
            .map_err(|_| CatalogError::InternalError)?;

        Ok(())
    }

    pub async fn notify_response_received(
        &self,
        _class: Class,
        _apex_name: &StoredName,
        _source: IpAddr,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc1996
        //   "4.8 Master Receives a NOTIFY Response from Slave
        //
        //    When a master server receives a NOTIFY response, it deletes this
        //    query from the retry queue, thus completing the "notification
        //    process" of "this" RRset change to "that" server."

        // TODO
    }
}

impl Catalog {
    /// Wrap a [`Zone`] so that we get notified when it is modified.
    fn wrap_zone(
        zone: Zone,
        zone_type: ZoneType,
        notify_tx: Sender<ZoneChangedMsg>,
    ) -> Zone {
        let diffs = Arc::new(Mutex::new(ZoneDiffs::new()));
        let zone_info = ZoneInfo {
            _catalog_member_id: None, // TODO
            zone_type,
            diffs,
        };

        let store = zone.into_inner();
        let new_store = CatalogZone::new(notify_tx, store, zone_info);
        Zone::new(new_store)
    }

    pub async fn run(&self) {
        self.running.store(true, Ordering::SeqCst);
        let lock = &mut self.notify_rx.lock().await;
        let notify_rx = lock.deref_mut();
        let mut refresh_timers = FuturesUnordered::new();

        // Clippy sees that StoredName uses interior mutability, but does not
        // know that the Hash impl for StoredName hashes only over the u8
        // label slice values which are fixed for a given StoredName.
        #[allow(clippy::mutable_key_type)]
        let mut time_tracking = HashMap::<(StoredName, Class), Timers>::new();

        for zone in self.zones().iter_zones() {
            let cat_zone = zone
                .as_ref()
                .as_any()
                .downcast_ref::<CatalogZone>()
                .unwrap();

            if matches!(cat_zone.info().zone_type, ZoneType::Secondary(..)) {
                let apex_name = zone.apex_name().clone();
                let class = zone.class();
                let key = (apex_name.clone(), class);
                if let Vacant(e) = time_tracking.entry(key.clone()) {
                    let read = zone.read();
                    if let Ok(Some(soa)) =
                        Self::read_soa(&read, apex_name).await
                    {
                        trace!(
                            "Creating REFRESH timer for zone {}",
                            zone.apex_name()
                        );
                        e.insert(Timers::new(&soa));
                    }
                }

                // On startup refresh all zones immediately.
                // TODO: Maybe add some fuzzyness to spread syncing of zones
                // out a bit.

                // Create a Tokio sleep future that will awaken when the
                // REFRESH interval expires, yielding the key of the zone
                // which is ready to be refreshed.
                let timer_info = TimerInfo::new(key, Ttl::ZERO);
                let fut = TimerInfoFuture::new(timer_info);
                refresh_timers.push(fut);
            }
        }

        loop {
            tokio::select! {
                biased;

                msg = notify_rx.recv() => {
                    let Some(msg) = msg else {
                        // The channel has been closed, i.e. the Catalog
                        // instance has been dropped. Stop performing
                        // background activiities for this catalog.
                        break;
                    };

                    trace!("Notify message received: {msg:?}");
                    self.handle_refresh(msg, &mut time_tracking, &refresh_timers).await;
                }

                Some(timer_info) = refresh_timers.next() => {
                    trace!("REFRESH timer expired: {timer_info:?}");

                    // Are we actively managing refreshing of this zone?
                    if let Some(tt) = time_tracking.get(&timer_info.key) {
                        // Was this zone already refreshed by a NOTIFY?
                        if let Ok(guard) = tt.last_refreshed.lock() {
                            if let Some(last_refreshed) = *guard {
                                if let Some(elapsed) = timer_info.end_instant.checked_duration_since(last_refreshed) {
                                    if elapsed < MIN_DURATION_BETWEEN_ZONE_REFRESHES {
                                        // Ignore this expired timer, the handling of the NOTIFY will have set a new one.
                                        continue;
                                    }
                                }
                            }
                        }
                    }

                    let (apex_name, class) = timer_info.key;

                    // Do we have the zone that is being updated?
                    let zones = self.zones();
                    let Some(zone) = zones.get_zone(&apex_name, class) else {
                        // The zone no longer exists, ignore.
                        continue;
                    };

                    // Make sure it's still a secondary and hasn't been
                    // deleted and re-added as a primary.
                    let cat_zone = zone
                        .as_ref()
                        .as_any()
                        .downcast_ref::<CatalogZone>()
                        .unwrap();

                    if let ZoneType::Secondary(primary_info, _) = &cat_zone.info().zone_type {
                        // If successfuly this will commit changes to the zone
                        // causing a notify event message to be sent which
                        // will be handled above.
                        self.sync_zone_if_outdated(zone, primary_info, &refresh_timers).await;
                    }
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
    }

    #[allow(clippy::mutable_key_type)]
    async fn handle_refresh(
        &self,
        msg: ZoneChangedMsg,
        time_tracking: &mut HashMap<(StoredName, Class), Timers>,
        refresh_timers: &FuturesUnordered<TimerInfoFuture>,
    ) {
        // Do we have the zone that is being updated?
        let zones = self.zones();
        let Some(zone) = zones.get_zone(&msg.apex_name, msg.class) else {
            warn!(
                "Ignoring change notification for unknown zone '{}'.",
                msg.apex_name
            );
            return;
        };

        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<CatalogZone>()
            .unwrap();

        // Are we the primary for the zone? We don't accept external
        // notifications for updates to a zone that we are authoritative for.
        let zone_info = cat_zone.info();

        let (source, primary_info, acl) = match (
            msg.source,
            &zone_info.zone_type,
        ) {
            (None, ZoneType::Primary(_)) => {
                // A local notification that a zone that we are primary for
                // has been changed locally. We don't do anything with this at
                // the moment.
                trace!(
                    "Local change occurred in primary zone '{}'",
                    msg.apex_name
                );
                return;
            }
            (None, ZoneType::Secondary(_, _)) => {
                // A local notification that a zone we are secondary for has
                // been changed locally. This happens when we apply changes
                // received via XFR from a remote primary to a local secondary
                // zone. Reset the REFRESH timer.
                trace!(
                    "Local change occurred in secondary zone '{}'",
                    msg.apex_name
                );

                let key = (zone.apex_name().clone(), zone.class());

                match time_tracking.entry(key.clone()) {
                    Occupied(e) => {
                        trace!(
                            "Resetting REFRESH timer for zone {}",
                            zone.apex_name()
                        );
                        let tt = e.get();
                        let timer_info = TimerInfo::new(key, tt.refresh);
                        let fut = TimerInfoFuture::new(timer_info);
                        refresh_timers.push(fut);
                    }
                    Vacant(e) => {
                        // An empty zone became non-empty so now we know the
                        // SOA timers to use to update it going forward.
                        let read = zone.read();
                        if let Ok(Some(soa)) =
                            Self::read_soa(&read, zone.apex_name().clone())
                                .await
                        {
                            trace!("Creating REFRESH timer for previously empty zone {}", zone.apex_name());
                            e.insert(Timers::new(&soa));

                            // Create a Tokio sleep future that will awaken when the
                            // REFRESH interval expires, yielding the key of the zone
                            // which is ready to be refreshed.
                            let timer_info =
                                TimerInfo::new(key, soa.refresh());
                            let fut = TimerInfoFuture::new(timer_info);
                            refresh_timers.push(fut);
                        } else {
                            trace!("Skipping creation of REFRESH timer for empty zone {}", zone.apex_name());
                        }
                    }
                }

                return;
            }
            (Some(source), ZoneType::Secondary(primary_info, acl)) => {
                // A remote notification that a zone that we are secondary for
                // has been updated on the remote server. If the notification
                // is legitimate we will want to check if the remote copy of
                // the zone is indeed newer than our copy and then fetch the
                // changes.
                trace!("Remote change notification received for secondary zone '{}'", msg.apex_name);
                (source, primary_info, acl)
            }
            (Some(_), ZoneType::Primary(_)) => {
                // An attempt by a remote entity to notify us of a change to a
                // zone that we are primary for. As only we can update a zone
                // that we are primary for, such a notification is spurious
                // and should be ignored.
                warn!("Ignoring spurious change notification for primary zone '{}'", msg.apex_name);
                return;
            }
        };

        // https://datatracker.ietf.org/doc/html/rfc1996#section-2
        //   "2.1. The following definitions are used in this document:
        //    ...
        //    Master          any authoritative server configured to be the
        //                    source of zone transfer for one or more slave
        //                    servers.
        //
        //    Primary Master  master server at the root of the zone transfer
        //                    dependency graph.  The primary master is named
        //                    in the zone's SOA MNAME field and optionally by
        //                    an NS RR. There is by definition only one
        //                    primary master server per zone.
        //
        //    Stealth         like a slave server except not listed in an NS
        //                    RR for the zone.  A stealth server, unless
        //                    explicitly configured to do otherwise, will set
        //                    the AA bit in responses and be capable of acting
        //                    as a master.  A stealth server will only be
        //                    known by other servers if they are given static
        //                    configuration data indicating its existence."
        //
        // https://datatracker.ietf.org/doc/html/rfc1996#section-3
        //   "3.10. If a slave receives a NOTIFY request from a host that is
        //    not a known master for the zone containing the QNAME, it should
        //    ignore the request and produce an error message in its
        //    operations log."

        // Check if the source is on the zone ACL list or if its IP
        // address resolves to the SOA MNAME or an apex NS name for the
        // zone being updated. If not, ignore the notification.

        let Some(primary_info) =
            Self::identify_primary(primary_info, acl, &source, &msg, zone)
                .await
        else {
            warn!(
                "NOTIFY for {}, from {source}: refused, no acl matches",
                msg.apex_name
            );
            return;
        };

        // https://datatracker.ietf.org/doc/html/rfc1996#section-4
        //   "4.7 Slave Receives a NOTIFY Request from a Master
        //
        //    When a slave server receives a NOTIFY request from one of
        //    its locally designated masters for the zone enclosing the
        //    given QNAME, with QTYPE=SOA and QR=0, it should enter the
        //    state it would if the zone's refresh timer had expired."

        self.sync_zone_if_outdated(zone, &primary_info, refresh_timers)
            .await;
    }

    async fn sync_zone_if_outdated(
        &self,
        zone: &Zone,
        primary_info: &PrimaryInfo,
        refresh_timers: &FuturesUnordered<TimerInfoFuture>,
    ) {
        // Determine the kind of transfer to use if the zone is outdated
        let rtype = match primary_info.xfr_mode {
            XfrMode::None => {
                warn!("Transfer not enabled for possibly outdated secondary zone '{}'", zone.apex_name());
                return;
            }
            XfrMode::AxfrOnly => Rtype::AXFR,
            XfrMode::AxfrAndIxfr => Rtype::IXFR,
        };

        // Query the SOA serial of the primary
        let udp_connect = UdpConnect::new(primary_info.addr);
        let mut dgram_config = dgram::Config::new();
        dgram_config.set_max_parallel(1);
        dgram_config.set_read_timeout(Duration::from_millis(1000));
        dgram_config.set_max_retries(1);
        dgram_config.set_udp_payload_size(Some(1400));
        let soa_query_client =
            dgram::Connection::with_config(udp_connect, dgram_config);

        let msg = MessageBuilder::new_vec();
        let mut msg = msg.question();
        msg.push((zone.apex_name(), Rtype::SOA)).unwrap();
        let msg = msg.into_message();
        let req = RequestMessage::new(msg);

        if let Ok(Some(soa)) =
            Self::read_soa(&zone.read(), zone.apex_name().clone()).await
        {
            let mut zone_is_outdated = false;
            let res = soa_query_client.send_request(req).get_response().await;
            if let Ok(msg) = res {
                if msg.no_error() {
                    if let Ok(answer) = msg.answer() {
                        let mut records = answer.limit_to::<Soa<_>>();
                        let record = records.next();
                        if let Some(Ok(record)) = record {
                            let serial_at_primary = record.data().serial();
                            {
                                zone_is_outdated =
                                    serial_at_primary > soa.serial();
                            }
                        }
                    }
                }
            }

            if !zone_is_outdated {
                // Create a Tokio sleep future that will awaken when the REFRESH
                // interval expires, yielding the key of the zone which is ready
                // to be refreshed.
                let key = (zone.apex_name().clone(), zone.class());
                let timer_info = TimerInfo::new(key, soa.refresh());
                let fut = TimerInfoFuture::new(timer_info);
                refresh_timers.push(fut);

                trace!("Zone {} is up-to-date", zone.apex_name());
                return;
            }
        } else {
            // Zone has no SOA, zone has never been populated from the primary.
        }

        // Update the zone from the primary using XFR.
        // TODO: Honor and reset SOA timers, e.g. regarding retries.
        // TODO: Use the appropriate client for XFR, e.g. UDP/TCP, re-use,
        // etc.
        // TODO: Extend the net-client code to handle multiple response
        // messages for XFR.
        info!(
            "Zone '{}' is outdated, attempting to sync zone by {rtype} from {}",
            zone.apex_name(),
            primary_info.addr,
        );

        let tcp_stream = match TcpStream::connect(primary_info.addr).await {
            Ok(stream) => stream,
            Err(err) => {
                error!(
                    "Unable to sync zone '{}' by {rtype} from {}: {err}",
                    zone.apex_name(),
                    primary_info.addr,
                );
                return;
            }
        };

        let mut stream_config = stream::Config::new();
        stream_config.set_response_timeout(Duration::from_secs(30));
        let (xfr_client, transport) =
            stream::Connection::with_config(tcp_stream, stream_config);

        tokio::spawn(async move {
            transport.run().await;
            trace!("XFR TCP connection terminated");
        });

        let msg = MessageBuilder::new_vec();
        let mut msg = msg.question();
        msg.push((zone.apex_name(), rtype)).unwrap();
        let msg = if rtype == Rtype::IXFR {
            let mut msg = msg.authority();
            let read = zone.read();
            let soa = Self::read_soa(&read, zone.apex_name().clone())
                .await
                .unwrap()
                .unwrap();
            msg.push((zone.apex_name(), 86400, soa)).unwrap();
            msg
        } else {
            msg.authority()
        };
        let msg = msg.into_message();
        let req = RequestMessage::new(msg);

        let expected_initial_soa_seen_count = match rtype {
            Rtype::AXFR => 2,
            Rtype::IXFR => 3,
            _ => unreachable!(),
        };

        pub fn mk_relative_name_iterator<'l>(
            apex_name: &Name<Bytes>,
            qname: &'l impl ToName,
        ) -> Result<impl Iterator<Item = &'l Label> + Clone, OutOfZone>
        {
            trace!("mk_relative_name_iterator({apex_name})`");
            let mut qname = qname.iter_labels().rev();
            // if let Some(qname_label) = qname_label {
            //     if qname_label.is_root() {
            //         trace!("mk_relative_name_iterator({apex_name}): Label is root '{qname_label}'");
            //         return Ok(qname);
            //     }
            // }
            for apex_label in apex_name.iter_labels().rev() {
                let qname_label = qname.next();
                trace!("mk_relative_name_iterator({apex_name}): Skipping label '{qname_label:?}'");
                if Some(apex_label) != qname_label {
                    error!("Qname is not in zone '{apex_name}'");
                    return Err(OutOfZone);
                }
            }
            Ok(qname)
        }

        let mut write = zone.write().await;
        // TODO: Handle the Err case when open() fails.
        if let Ok(writable) = write.open(true).await {
            let mut req = xfr_client.send_streaming_request(req);
            let mut i = 0;
            let mut initial_soa_serial = None;
            let mut initial_soa_serial_seen_count = 0;
            loop {
                i += 1;
                let res = req.get_response().await;
                if let Ok(msg) = res {
                    trace!("Received response {i}");
                    if msg.no_error() {
                        if let Ok(answer) = msg.answer() {
                            let records =
                                answer.limit_to::<AllRecordData<_, _>>();
                            for record in records.flatten() {
                                trace!("XFR record: {record:?}");

                                let mut end_node: Option<
                                    Box<dyn WritableZoneNode>,
                                > = None;

                                let name = mk_relative_name_iterator(
                                    zone.apex_name(),
                                    record.owner(),
                                )
                                .unwrap();

                                for label in name {
                                    trace!("Relativised label: {label}");
                                    end_node =
                                        Some(
                                            match end_node {
                                                Some(new_node) => new_node
                                                    .update_child(label),
                                                None => writable
                                                    .update_child(label),
                                            }
                                            .await
                                            .unwrap(),
                                        );
                                }
                                let rtype = record.rtype();
                                let ttl = record.ttl();
                                let data = record.into_data();
                                let mut rrset = Rrset::new(rtype, ttl);

                                match data {
                                    AllRecordData::A(v) => {
                                        rrset.push_data(ZoneRecordData::A(v))
                                    }
                                    AllRecordData::Cname(v) => rrset
                                        .push_data(ZoneRecordData::Cname(
                                            Cname::new(
                                                v.into_cname().to_name(),
                                            ),
                                        )),
                                    AllRecordData::Hinfo(v) => rrset
                                        .push_data(ZoneRecordData::Hinfo(v)),
                                    AllRecordData::Mb(v) => rrset.push_data(
                                        ZoneRecordData::Mb(Mb::new(
                                            v.into_madname().to_name(),
                                        )),
                                    ),
                                    AllRecordData::Md(v) => rrset.push_data(
                                        ZoneRecordData::Md(Md::new(
                                            v.into_madname().to_name(),
                                        )),
                                    ),
                                    AllRecordData::Mf(v) => rrset.push_data(
                                        ZoneRecordData::Mf(Mf::new(
                                            v.into_madname().to_name(),
                                        )),
                                    ),
                                    AllRecordData::Mg(v) => rrset.push_data(
                                        ZoneRecordData::Mg(Mg::new(
                                            v.into_madname().to_name(),
                                        )),
                                    ),
                                    // AllRecordData::Minfo(v) => rrset.push_data(ZoneRecordData::Minfo(Minfo::new(v))),
                                    // AllRecordData::Mr(v) => rrset.push_data(ZoneRecordData::Mr(v)),
                                    AllRecordData::Mx(v) => rrset.push_data(
                                        ZoneRecordData::Mx(Mx::new(
                                            v.preference(),
                                            v.exchange().to_name(),
                                        )),
                                    ),
                                    AllRecordData::Ns(v) => rrset.push_data(
                                        ZoneRecordData::Ns(Ns::new(
                                            v.into_nsdname().to_name(),
                                        )),
                                    ),
                                    AllRecordData::Ptr(v) => rrset.push_data(
                                        ZoneRecordData::Ptr(Ptr::new(
                                            v.into_ptrdname().to_name(),
                                        )),
                                    ),
                                    AllRecordData::Soa(v) => {
                                        if let Some(initial_soa_serial) =
                                            initial_soa_serial
                                        {
                                            if initial_soa_serial
                                                == v.serial()
                                            {
                                                // AXFR end SOA detected.
                                                // Notify transport that no
                                                // more responses are
                                                // expected.
                                                initial_soa_serial_seen_count += 1;
                                                if initial_soa_serial_seen_count == expected_initial_soa_seen_count {
                                                    trace!("Closing response stream at record nr {i} (soa seen count = {initial_soa_serial_seen_count})");
                                                    req.stream_complete();
                                                }
                                            }
                                        } else {
                                            initial_soa_serial =
                                                Some(v.serial());
                                            initial_soa_serial_seen_count = 1;
                                        }

                                        rrset.push_data(ZoneRecordData::Soa(
                                            Soa::new(
                                                v.mname().to_name(),
                                                v.rname().to_name(),
                                                v.serial(),
                                                v.refresh(),
                                                v.retry(),
                                                v.expire(),
                                                v.minimum(),
                                            ),
                                        ))
                                    }
                                    AllRecordData::Txt(v) => rrset
                                        .push_data(ZoneRecordData::Txt(v)),
                                    AllRecordData::Aaaa(v) => rrset
                                        .push_data(ZoneRecordData::Aaaa(v)),
                                    AllRecordData::Cdnskey(v) => rrset
                                        .push_data(ZoneRecordData::Cdnskey(
                                            v,
                                        )),
                                    AllRecordData::Cds(v) => rrset
                                        .push_data(ZoneRecordData::Cds(v)),
                                    AllRecordData::Dname(v) => rrset
                                        .push_data(ZoneRecordData::Dname(
                                            Dname::new(
                                                v.into_dname().to_name(),
                                            ),
                                        )),
                                    // AllRecordData::Dnskey(v) => rrset.push_data(ZoneRecordData::Dnskey(v),
                                    // AllRecordData::Rrsig(v) => rrset.push_data(ZoneRecordData::Rrsig(v)),
                                    AllRecordData::Nsec(v) => rrset
                                        .push_data(ZoneRecordData::Nsec(
                                            Nsec::new(
                                                v.next_name().to_name(),
                                                v.types().clone(),
                                            ),
                                        )),
                                    AllRecordData::Ds(v) => {
                                        rrset.push_data(ZoneRecordData::Ds(v))
                                    }
                                    AllRecordData::Nsec3(v) => rrset
                                        .push_data(ZoneRecordData::Nsec3(v)),
                                    AllRecordData::Nsec3param(v) => rrset
                                        .push_data(
                                            ZoneRecordData::Nsec3param(v),
                                        ),
                                    // AllRecordData::Srv(v) => rrset.push_data(ZoneRecordData::Srv(v)),
                                    AllRecordData::Zonemd(v) => rrset
                                        .push_data(ZoneRecordData::Zonemd(v)),
                                    // AllRecordData::Null(v) => rrset.push_data(ZoneRecordData::Null(v)),
                                    // AllRecordData::Svcb(v) => rrset.push_data(ZoneRecordData::Svcb(v)),
                                    // AllRecordData::Https(v) => rrset.push_data(ZoneRecordData::Https(v)),
                                    // AllRecordData::Tsig(v) => rrset.push_data(ZoneRecordData::Tsig(v)),
                                    // AllRecordData::Opt(v) => rrset.push_data(ZoneRecordData::Opt(v)),
                                    AllRecordData::Unknown(v) => rrset
                                        .push_data(ZoneRecordData::Unknown(
                                            v,
                                        )),
                                    _ => todo!(),
                                }
                                trace!("Adding RRset: {rrset:?}");
                                let rrset = SharedRrset::new(rrset);
                                match end_node {
                                    Some(n) => {
                                        trace!("Adding RRset at end_node");
                                        n.update_rrset(rrset).await.unwrap()
                                    }
                                    None => {
                                        trace!("Adding RRset at root");
                                        writable
                                            .update_rrset(rrset)
                                            .await
                                            .unwrap();
                                    }
                                }
                            }
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        write.commit(false).await.unwrap();

        info!(
            "Zone '{}' has been updated by {rtype} from {}",
            zone.apex_name(),
            primary_info.addr,
        );
    }

    #[allow(clippy::borrowed_box)]
    async fn read_soa(
        read: &Box<dyn ReadableZone>,
        qname: Name<Bytes>,
    ) -> Result<Option<Soa<Name<Bytes>>>, OutOfZone> {
        let answer = match read.is_async() {
            true => read.query_async(qname, Rtype::SOA).await,
            false => read.query(qname, Rtype::SOA),
        }?;

        if let AnswerContent::Data(rrset) = answer.content() {
            if let ZoneRecordData::Soa(soa) = rrset.first().unwrap().data() {
                return Ok(Some(soa.clone()));
            }
        }

        Ok(None)
    }

    #[allow(clippy::borrowed_box)]
    async fn read_rrset(
        read: &Box<dyn ReadableZone>,
        qname: Name<Bytes>,
        qtype: Rtype,
    ) -> Result<Option<SharedRrset>, OutOfZone> {
        let answer = match read.is_async() {
            true => read.query_async(qname, qtype).await,
            false => read.query(qname, qtype),
        }?;

        if let AnswerContent::Data(rrset) = answer.content() {
            return Ok(Some(rrset.clone()));
        }

        Ok(None)
    }

    async fn identify_primary<'a>(
        primary_info: &'a PrimaryInfo,
        acl: &Acl,
        source: &IpAddr,
        msg: &ZoneChangedMsg,
        zone: &Zone,
    ) -> Option<Cow<'a, PrimaryInfo>> {
        trace!("Does the source IP {source} match the primary info for the zone?");
        if primary_info.addr.ip() == *source {
            return Some(Cow::Borrowed(primary_info));
        }

        trace!("Does ACL contain source IP {source}?");
        if let Some(acl_entry) = acl.get(source) {
            let socket_addr = SocketAddr::new(
                *source,
                acl_entry.port.unwrap_or(DEF_PRIMARY_PORT),
            );
            let primary_info = PrimaryInfo::new(socket_addr);
            return Some(Cow::Owned(primary_info));
        }

        let mut allowed = false;
        let mut unresolved_names = vec![];
        let read = zone.read();

        trace!(
            "No. Fetching the SOA MNAME value for zone {}",
            msg.apex_name
        );

        // Is the SOA MNAME IP defined in the zone?
        let mut mname_addr: Option<IpAddr> = None;

        if let Ok(Some(soa)) =
            Self::read_soa(&read, msg.apex_name.clone()).await
        {
            trace!("SOA MNAME is {}", soa.mname());
            if source.is_ipv4() {
                if let Ok(Some(res)) =
                    Self::read_rrset(&read, soa.mname().clone(), Rtype::A)
                        .await
                {
                    Self::match_a(res, source, &mut mname_addr);
                }
            } else if let Ok(Some(res)) =
                Self::read_rrset(&read, soa.mname().clone(), Rtype::AAAA)
                    .await
            {
                Self::match_aaaa(res, source, &mut mname_addr);
            }
        }

        // Is the SOA MNAME IP the same as the source?
        match mname_addr {
            Some(addr) => {
                trace!("Found {addr} for SOA MNAME");
                allowed = *source == addr;
            }
            None => {
                trace!("No A/AAAA record found SOA MNAME");
                unresolved_names.push(mname_addr);
            }
        }

        // If the source IP address is not the SOA MNAME IP address,
        // try to find out if it is one of the primaries for the zone.
        trace!("Is the source IP {source} that of the SOA MNAME?");
        if !allowed {
            trace!("No. Fetching apex NS records for zone {}", msg.apex_name);
            // Does the zone apex have NS records and are their
            // addresses defined in the zone?
            if let Ok(Some(res)) =
                Self::read_rrset(&read, msg.apex_name.clone(), Rtype::NS)
                    .await
            {
                let mut data_iter = res.data().iter();
                while let Some(ZoneRecordData::Ns(ns)) = data_iter.next() {
                    let mut primary_addr: Option<IpAddr> = None;
                    if source.is_ipv4() {
                        if let Ok(Some(res)) = Self::read_rrset(
                            &read,
                            ns.nsdname().clone(),
                            Rtype::A,
                        )
                        .await
                        {
                            Self::match_a(res, source, &mut primary_addr);
                        }
                    } else if let Ok(Some(res)) = Self::read_rrset(
                        &read,
                        ns.nsdname().clone(),
                        Rtype::AAAA,
                    )
                    .await
                    {
                        Self::match_aaaa(res, source, &mut primary_addr);
                    }

                    match primary_addr {
                        Some(addr) => {
                            trace!("Found {addr} for NS record {ns}");
                            allowed = *source == addr;
                        }
                        None => {
                            trace!("No A/AAAA record found NS record {ns}");
                            unresolved_names.push(primary_addr);
                        }
                    }

                    if allowed {
                        trace!("Notify from primary at {source} allowed via NS record {ns}");
                        break;
                    }
                }
            }
        }

        // If no NS record IP address was found that matches the source IP
        // address, try resolving the unresolved names and seeing then if
        // any of the addresses match the source IP.
        // if !allowed {
        //     let qtype = if source.is_ipv4() {
        //         Rtype::A
        //     } else {
        //         Rtype::AAAA
        //     };
        //     for name in unresolved_names {
        //         let mut msg = mk_builder_for_target();
        //         msg.header_mut().set_rd(true);
        //         let mut msg = msg.question();
        //         msg.push((Name::vec_from_str("example.com").unwrap(), qtype))
        //             .unwrap();
        //         let msg = msg.into_message();
        //         let req = RequestMessage::new(msg);
        //         let res = self.client.send_request(req).get_response().await;
        //     }
        // }

        if allowed {
            let socket_addr = SocketAddr::new(*source, DEF_PRIMARY_PORT);
            let primary_info = PrimaryInfo::new(socket_addr);
            return Some(Cow::Owned(primary_info));
        } else {
            None
        }
    }

    fn match_a(
        res: SharedRrset,
        source: &IpAddr,
        out_addr: &mut Option<IpAddr>,
    ) {
        if let Some(Some(a)) = res
            .data()
            .iter()
            .map(|rrset| {
                if let ZoneRecordData::A(a) = rrset {
                    trace!("Checking A record {a}");
                    Some(a)
                } else {
                    None
                }
            })
            .find(|a| a.map(|a| IpAddr::V4(a.addr())) == Some(*source))
        {
            *out_addr = Some(IpAddr::V4(a.addr()));
        }
    }

    fn match_aaaa(
        res: SharedRrset,
        source: &IpAddr,
        out_addr: &mut Option<IpAddr>,
    ) {
        if let Some(Some(aaaa)) = res
            .data()
            .iter()
            .map(|rrset| {
                if let ZoneRecordData::Aaaa(aaaa) = rrset {
                    trace!("Checking AAAA record {aaaa}");
                    Some(aaaa)
                } else {
                    None
                }
            })
            .find(|aaaa| {
                aaaa.map(|aaaa| IpAddr::V6(aaaa.addr())) == Some(*source)
            })
        {
            *out_addr = Some(IpAddr::V6(aaaa.addr()));
        }
    }
}

impl Catalog {
    pub fn zones(&self) -> Arc<ZoneTree> {
        self.loaded_arc.read().unwrap().clone()
    }
}

impl Catalog {
    fn update_lodaded_arc(&self) {
        *self.loaded_arc.write().unwrap() = self.member_zones.load_full();
    }
}

async fn send_zone_changed_msg(
    tx: &Sender<ZoneChangedMsg>,
    msg: ZoneChangedMsg,
) -> Result<(), SendError<ZoneChangedMsg>> {
    tx.send(msg).await
}

/// Create a [`Catalog`] from an RFC 9432 catalog zone.
// impl<ClientTransportFactory> From<(Zone, ClientTransportFactory)>
//     for Catalog
// {
//     fn from(
//         (zone, client_transport_factory): (Zone, ClientTransportFactory),
//     ) -> Self {
//         let mut catalog = Catalog::new(client_transport_factory);
//         // TODO: Parse the given RFC 9432 catalog zone and add appropriate
//         // ZoneInfo entries to the new catalog.
//         todo!()
//     }
// }

/// Produce an RFC 9432 catalog zone for a [`Catalog`].
// impl From<Catalog> for Zone {
//     fn from(value: Catalog) -> Self {
//         todo!()
//     }
// }

//------------ CatalogZone ---------------------------------------------------

#[derive(Debug)]
pub struct CatalogZone {
    notify_tx: Sender<ZoneChangedMsg>,
    store: Arc<dyn ZoneStore>,
    info: ZoneInfo,
}

impl CatalogZone {
    fn new(
        notify_tx: Sender<ZoneChangedMsg>,
        store: Arc<dyn ZoneStore>,
        info: ZoneInfo,
    ) -> Self {
        Self {
            notify_tx,
            store,
            info,
        }
    }
}

impl CatalogZone {
    pub fn info(&self) -> &ZoneInfo {
        &self.info
    }
}

impl ZoneStore for CatalogZone {
    /// Gets the CLASS of this zone.
    fn class(&self) -> Class {
        self.store.class()
    }

    /// Gets the apex name of this zone.
    fn apex_name(&self) -> &StoredName {
        self.store.apex_name()
    }

    /// Gets a read interface to this zone.
    fn read(self: Arc<Self>) -> Box<dyn ReadableZone> {
        self.store.clone().read()
    }

    /// Gets a write interface to this zone.
    fn write(
        self: Arc<Self>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>> + Send>> {
        let fut = self.store.clone().write();
        let notify_tx = self.notify_tx.clone();
        Box::pin(async move {
            let writable_zone = fut.await;
            let writable_zone = WritableCatalogZone {
                catalog_zone: self.clone(),
                notify_tx,
                writable_zone,
            };
            Box::new(writable_zone) as Box<dyn WritableZone>
        })
    }

    fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }
}

//------------ WritableCatalogZone -------------------------------------------

struct WritableCatalogZone {
    catalog_zone: Arc<CatalogZone>,
    notify_tx: Sender<ZoneChangedMsg>,
    writable_zone: Box<dyn WritableZone>,
}

impl WritableZone for WritableCatalogZone {
    fn open(
        &self,
        _create_diff: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>
                + Send,
        >,
    > {
        self.writable_zone.open(true)
    }

    fn commit(
        &mut self,
        bump_soa_serial: bool,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<ZoneDiff>, io::Error>> + Send>,
    > {
        let fut = self.writable_zone.commit(bump_soa_serial);
        let notify_tx = self.notify_tx.clone();
        let cat_zone = self.catalog_zone.clone();
        Box::pin(async move {
            match fut.await {
                Ok(diff) => {
                    if let Some(diff) = &diff {
                        trace!("Captured diff: {diff:?}");
                        cat_zone.info().add_diff(diff.clone()).await;
                    }

                    let msg = ZoneChangedMsg {
                        class: cat_zone.class(),
                        apex_name: cat_zone.apex_name().clone(),
                        source: None,
                    };

                    send_zone_changed_msg(&notify_tx, msg).await.unwrap();

                    Ok(diff)
                }
                Err(err) => Err(err),
            }
        })
    }
}

//------------ CatalogError --------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub enum CatalogError {
    NotRunning,
    InternalError,
    UnknownZone,
}
