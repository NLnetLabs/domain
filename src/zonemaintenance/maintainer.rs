//! Experimental storing, querying and syncing of a collection of zones.
// TODO: Add lifecycle hooks for callers, e.g. zone added, zone removed, zone
// expired, zone refreshed.?
// TODO: Support RFC-1995 "condensation" (aka "delta compression")? Related
// reading: https://kb.isc.org/docs/axfr-style-ixfr-explained
use core::any::Any;
use core::fmt::Debug;
use core::marker::{Send, Sync};
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use std::borrow::ToOwned;
use std::boxed::Box;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::fmt::Display;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::string::{String, ToString};
use std::sync::Arc;
use std::vec::Vec;

use arc_swap::ArcSwap;
use bytes::Bytes;
use futures::stream::FuturesUnordered;
use octseq::Octets;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, trace, warn};

use crate::base::iana::{Class, Opcode, OptRcode};
use crate::base::net::IpAddr;
use crate::base::{
    Message, MessageBuilder, Name, Rtype, Serial, ToName, Ttl,
};
use crate::net;
use crate::net::client::dgram::{self, Connection};
use crate::net::client::protocol::UdpConnect;
use crate::net::client::request::{
    self, RequestMessage, RequestMessageMulti, SendRequest, SendRequestMulti,
};
use crate::net::client::tsig::AuthenticatedRequestMessage;
use crate::rdata::{Soa, ZoneRecordData};
use crate::tsig::{Key, KeyStore};
use crate::zonetree::error::{OutOfZone, ZoneTreeModificationError};
use crate::zonetree::{
    AnswerContent, ReadableZone, SharedRrset, StoredName, WritableZone,
    WritableZoneNode, Zone, ZoneDiff, ZoneKey, ZoneStore, ZoneTree,
};

use super::types::{
    Event, NotifySrcDstConfig, NotifyStrategy, TransportStrategy, XfrConfig,
    XfrStrategy, ZoneChangedMsg, ZoneConfig, ZoneDiffs, ZoneInfo,
    ZoneNameServers, ZoneRefreshCause, ZoneRefreshInstant, ZoneRefreshState,
    ZoneRefreshStatus, ZoneRefreshTimer, ZoneReport, ZoneReportDetails,
    IANA_DNS_PORT_NUMBER, MIN_DURATION_BETWEEN_ZONE_REFRESHES,
};
use crate::net::server::message::Request;
use crate::net::server::middleware::notify::{Notifiable, NotifyError};
use crate::net::server::middleware::tsig::{
    Authentication, MaybeAuthenticated,
};
use crate::net::server::middleware::xfr::{
    XfrDataProvider, XfrDataProviderError,
};
use crate::net::xfr::processing::{
    ProcessingError, XfrEvent, XfrResponseProcessor,
};
use crate::zonetree::xfr_event_handler::ZoneUpdateEventHandler;

//------------ ConnectionFactory ---------------------------------------------

pub type FactoryResult<SR, E> = Box<
    dyn Future<Output = Result<Option<Box<SR>>, E>> + Send + Sync + 'static,
>;

pub type UdpClientResult<Octs, E> = FactoryResult<
    dyn SendRequest<RequestMessage<Octs>> + Send + Sync + 'static,
    E,
>;

pub type TcpClientResult<Octs, E> = FactoryResult<
    dyn SendRequestMulti<RequestMessageMulti<Octs>> + Send + Sync + 'static,
    E,
>;

pub trait ConnectionFactory {
    type Error: Display;

    #[allow(clippy::type_complexity)]
    fn get_udp<K, Octs>(
        &self,
        dest: SocketAddr,
        key: Option<K>,
    ) -> Pin<UdpClientResult<Octs, Self::Error>>
    where
        K: Clone + Debug + AsRef<Key> + Send + Sync + 'static,
        Octs: Octets + Debug + Send + Sync + 'static;

    #[allow(clippy::type_complexity)]
    fn get_tcp<K, Octs>(
        &self,
        dest: SocketAddr,
        key: Option<K>,
    ) -> Pin<TcpClientResult<Octs, Self::Error>>
    where
        K: Clone + Debug + AsRef<Key> + Send + Sync + 'static,
        Octs: Octets + Debug + Send + Sync + 'static;
}

//------------ Config --------------------------------------------------------

/// Configuration for a ZoneMaintainer.
#[derive(Debug, Default)]
pub struct Config<KS, CF: ConnectionFactory>
where
    KS: Deref,
    KS::Target: KeyStore,
{
    /// A store of TSIG keys that can optionally be used to lookup keys when
    /// TSIG signing/validating.
    key_store: KS,

    /// A connection factory for making outbound requests to primary servers
    /// to fetch remote zones.
    conn_factory: CF,
}

impl<KS, CF: ConnectionFactory + Default> Config<KS, CF>
where
    KS: Deref,
    KS::Target: KeyStore,
{
    /// Creates a new config using the provided [`KeyStore`].
    pub fn new(key_store: KS) -> Self {
        Self {
            key_store,
            conn_factory: CF::default(),
        }
    }

    pub fn new_with_conn_factory(key_store: KS, conn_factory: CF) -> Self {
        Self {
            key_store,
            conn_factory,
        }
    }
}

//------------ ZoneMaintainer -------------------------------------------------

/// Maintain a set of zones by using NOTIFY and XFR to keep them up-to-date.
///
/// https://www.rfc-editor.org/rfc/rfc1034#section-4.3.5
/// 4.3.5. Zone maintenance and transfers
///
/// "Part of the job of a zone administrator is to maintain the zones at all
///  of the name servers which are authoritative for the zone.  When the
///  inevitable changes are made, they must be distributed to all of the name
///  servers.  While this distribution can be accomplished using FTP or some
///  other ad hoc procedure, the preferred method is the zone transfer part of
///  the DNS protocol."
#[derive(Debug)]
pub struct ZoneMaintainer<KS, CF: ConnectionFactory>
where
    KS: Deref,
    KS::Target: KeyStore,
{
    config: Arc<ArcSwap<Config<KS, CF>>>,
    pending_zones: Arc<RwLock<HashMap<ZoneKey, Zone>>>,
    member_zones: Arc<ArcSwap<ZoneTree>>,
    loaded_arc: std::sync::RwLock<Arc<ZoneTree>>,
    event_rx: Mutex<Receiver<Event>>,
    event_tx: Sender<Event>,
    running: AtomicBool,
}

impl<KS, CF: ConnectionFactory + Default> Default for ZoneMaintainer<KS, CF>
where
    KS: Deref + Default,
    KS::Target: KeyStore,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<KS, CF: ConnectionFactory + Default> ZoneMaintainer<KS, CF>
where
    KS: Deref + Default,
    KS::Target: KeyStore,
{
    pub fn new() -> Self {
        Self::new_with_config(Config::default())
    }

    pub fn new_with_config(config: Config<KS, CF>) -> Self {
        let pending_zones = Default::default();
        let member_zones = ZoneTree::new();
        let member_zones = Arc::new(ArcSwap::from_pointee(member_zones));
        let loaded_arc = std::sync::RwLock::new(member_zones.load_full());
        let (event_tx, event_rx) = mpsc::channel(10);
        let event_rx = Mutex::new(event_rx);
        let config = Arc::new(ArcSwap::from_pointee(config));

        ZoneMaintainer {
            // cat_zone,
            config,
            pending_zones,
            member_zones,
            loaded_arc,
            event_rx,
            event_tx,
            running: AtomicBool::new(false),
        }
    }
}

impl<KS, CF> ZoneMaintainer<KS, CF>
where
    KS: Deref + Send + Sync + 'static,
    KS::Target: KeyStore,
    <KS::Target as KeyStore>::Key:
        Clone + Debug + Display + Sync + Send + 'static,
    CF: ConnectionFactory + Send + Sync + 'static,
{
    pub async fn run(&self) {
        self.running.store(true, Ordering::SeqCst);
        let lock = &mut self.event_rx.lock().await;
        let event_rx = lock.deref_mut();
        let mut refresh_timers = FuturesUnordered::new();

        // Clippy sees that StoredName uses interior mutability, but does not
        // know that the Hash impl for StoredName hashes only over the u8
        // label slice values which are fixed for a given StoredName.
        #[allow(clippy::mutable_key_type)]
        let time_tracking = HashMap::<ZoneKey, ZoneRefreshState>::new();
        let time_tracking = Arc::new(RwLock::new(time_tracking));

        for zone in self.zones().iter_zones() {
            let cat_zone = zone
                .as_ref()
                .as_any()
                .downcast_ref::<MaintainedZone>()
                .unwrap();

            let zone_config = &cat_zone.info().config;

            // TODO: This shouldn't check is_primary() but rather
            // if it has notify targets.
            if zone_config.is_primary() {
                // https://datatracker.ietf.org/doc/html/rfc1996#autoid-4
                // 4. Details and Examples
                //   "4.1. Retaining query state information across host
                //    reboots is optional, but it is reasonable to simply
                //    execute an SOA NOTIFY transaction on each authority zone
                //    when a server first starts."
                Self::send_notify(
                    zone,
                    &zone_config.send_notify_to,
                    self.config.clone(),
                )
                .await;
            }

            if zone_config.is_secondary() {
                match Self::track_zone_freshness(zone, time_tracking.clone())
                    .await
                {
                    Ok(soa_refresh) => {
                        // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.5
                        // 4.3.5. Zone maintenance and transfers
                        //   ..
                        //   "Whenever a new zone is loaded in a secondary,
                        //    the secondary waits REFRESH seconds before
                        //    checking with the primary for a new serial."
                        Self::refresh_zone_at(
                            ZoneRefreshCause::SoaRefreshTimerAfterStartup,
                            zone.key(),
                            soa_refresh,
                            &mut refresh_timers,
                        );
                    }

                    Err(_) => {
                        todo!();
                    }
                }
            }
        }

        loop {
            tokio::select! {
                biased;

                msg = event_rx.recv() => {
                    let Some(event) = msg else {
                        // The channel has been closed, i.e. the
                        // ZoneMaintainer instance has been dropped. Stop
                        // performing background activiities for this
                        // ZoneMaintainer.
                        break;
                    };

                    match event {
                        Event::ZoneChanged(msg) => {
                            trace!("Notify message received: {msg:?}");
                            let zones = self.zones();
                            let time_tracking = time_tracking.clone();
                            let event_tx = self.event_tx.clone();
                            let pending_zones = self.pending_zones.clone();
                            let config = self.config.clone();
                            tokio::spawn(
                                Self::handle_notify(
                                    zones, pending_zones, msg, time_tracking, event_tx, config,
                                )
                            );
                        }

                        Event::ZoneAdded(key) => {
                            // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.5
                            // 4.3.5. Zone maintenance and transfers
                            //   ..
                            //   "Whenever a new zone is loaded in a secondary, the secondary
                            //    waits REFRESH seconds before checking with the primary for a
                            //    new serial."

                            let mut pending_zones = self.pending_zones.write().await;
                            if let Some(zone) = pending_zones.get(&key) {
                                if let Ok(soa_refresh) = Self::track_zone_freshness(zone, time_tracking.clone()).await {
                                    // If the zone already has a SOA REFRESH
                                    // it is not empty and we can make it
                                    // active immediately.
                                    if soa_refresh.is_some() {
                                        trace!("Removing zone '{}' from the pending set as it has a SOA REFRESH", key.0);
                                        let zone = pending_zones.remove(&key).unwrap();
                                        self.insert_active_zone(zone).await.unwrap();
                                    }
                                    Self::refresh_zone_at(
                                        ZoneRefreshCause::SoaRefreshTimerAfterZoneAdded,
                                        key,
                                        soa_refresh,
                                        &mut refresh_timers);
                                }
                            }
                        }

                        // TODO
                        // Event::ZoneRemoved(_key) => {
                        // }

                        Event::ZoneRefreshRequested { key, at, cause } => {
                            Self::refresh_zone_at(cause, key, at, &mut refresh_timers);
                        }

                        Event::ZoneStatusRequested { key, tx } => {
                            let details = if self.pending_zones.read().await.contains_key(&key) {
                                ZoneReportDetails::PendingSecondary
                            } else if let Some(zone_refresh_info) = time_tracking.read().await.get(&key) {
                                ZoneReportDetails::Secondary(*zone_refresh_info)
                            } else {
                                ZoneReportDetails::Primary
                            };

                            let timers = refresh_timers
                                .iter()
                                .filter_map(|timer| {
                                    if timer.refresh_instant.key == key {
                                        Some(timer.refresh_instant.clone())
                                    } else {
                                        None
                                    }
                                })
                                .collect();

                            let zones = self.zones();
                            if let Some(zone) = self.pending_zones.read().await.get(&key).or_else(|| zones.get_zone(&key.0, key.1)) {
                                let cat_zone = zone
                                .as_ref()
                                .as_any()
                                .downcast_ref::<MaintainedZone>()
                                .unwrap();

                                let zone_info = cat_zone.info().clone();

                                let report = ZoneReport::new(key, details, timers, zone_info);

                                if let Err(_err) = tx.send(report) {
                                    // TODO
                                }
                            } else {
                                warn!("Zone '{}' not found for zone status request.", key.0);
                            };
                        }
                    }
                }

                Some(timer_info) = refresh_timers.next() => {
                    // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.5
                    // 4.3.5. Zone maintenance and transfers
                    //   ..
                    //   "To detect changes, secondaries just check the SERIAL
                    //    field of the SOA for the zone."
                    //   ..
                    //   "The periodic polling of the secondary servers is
                    //    controlled by parameters in the SOA RR for the zone,
                    //    which set the minimum acceptable polling intervals.
                    //    The parameters are called REFRESH, RETRY, and
                    //    EXPIRE.  Whenever a new zone is loaded in a
                    //    secondary, the secondary waits REFRESH seconds
                    //    before checking with the primary for a new serial."
                    trace!("REFRESH timer fired: {timer_info:?}");

                    // Are we actively managing refreshing of this zone?
                    let mut tt = time_tracking.write().await;
                    if let Some(zone_refresh_info) = tt.get_mut(&timer_info.key) {
                        // Do we have the zone that is being updated?
                        let pending_zones = self.pending_zones.read().await;
                        let zones = self.zones();
                        let key = timer_info.key;

                        let (is_pending_zone, zone) = {
                            // Is the zone pending?
                            if let Some(zone) = pending_zones.get(&key) {
                                (true, zone)
                            } else {
                                let (apex_name, class) = key.clone();
                                let Some(zone) = zones.get_zone(&apex_name, class) else {
                                    // The zone no longer exists, ignore.
                                    continue;
                                };
                                (false, zone)
                            }
                        };

                        // Make sure it's still a secondary and hasn't been
                        // deleted and re-added as a primary.
                        let cat_zone = zone
                            .as_ref()
                            .as_any()
                            .downcast_ref::<MaintainedZone>()
                            .unwrap();

                        if cat_zone.info().config.is_secondary() {
                            // If successful this will commit changes to the
                            // zone causing a notify event message to be sent
                            // which will be handled above.
                            match Self::refresh_zone_and_update_state(
                                    timer_info.cause,
                                    zone,
                                    None,
                                    zone_refresh_info,
                                    self.event_tx.clone(),
                                    self.config.clone(),
                                )
                                .await
                            {
                                Ok(()) => {
                                    if is_pending_zone {
                                        trace!("Removing zone '{}' from the pending set as it was successfully refreshed", key.0);
                                        drop(pending_zones);
                                        let mut pending_zones = self.pending_zones.write().await;
                                        let zone = pending_zones.remove(&key).unwrap();
                                        self.insert_active_zone(zone).await.unwrap();
                                    }
                                }

                                Err(_) => {
                                    // TODO
                                }
                            }
                        } else {
                            // TODO
                        }
                    }
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
    }

    pub async fn insert_zone(
        &self,
        zone: TypedZone,
    ) -> Result<(), ZoneTreeModificationError> {
        self.insert_zones([zone]).await
    }

    pub async fn insert_zones<T: Iterator<Item = TypedZone>>(
        &self,
        zones: impl IntoIterator<Item = TypedZone, IntoIter = T>,
    ) -> Result<(), ZoneTreeModificationError> {
        let mut new_zones = self.zones().deref().clone();

        for zone in zones {
            let is_secondary = zone.zone_type().is_secondary();
            let zone = Self::wrap_zone(zone, self.event_tx.clone());
            let key = zone.key();
            let zone_name = &key.0;

            if is_secondary {
                // Don't add secondary zones immediately as they may be empty
                // until refreshed. Instead add them in run() once it has been
                // determined if they are empty or that the initial refresh
                // has been performed successfully. This prevents callers of
                // get_zone() or find_zone() attempting to use an empty zone.
                trace!(
                    "Adding new secondary zone '{zone_name}' to the pending set"
                );
                self.pending_zones.write().await.insert(zone.key(), zone);
            } else {
                trace!(
                    "Adding new primary zone '{zone_name}' to the active set"
                );
                Self::update_known_nameservers_for_zone(&zone).await;
                new_zones.insert_zone(zone)?;
            }

            self.event_tx.send(Event::ZoneAdded(key)).await.unwrap();
        }

        self.member_zones.store(Arc::new(new_zones));
        self.update_lodaded_arc();

        Ok(())
    }

    async fn insert_active_zone(
        &self,
        zone: Zone,
    ) -> Result<(), ZoneTreeModificationError> {
        Self::update_known_nameservers_for_zone(&zone).await;

        let mut new_zones = self.zones().deref().clone();
        new_zones.insert_zone(zone)?;
        self.member_zones.store(Arc::new(new_zones));
        self.update_lodaded_arc();
        Ok(())
    }
}

impl<KS, CF> ZoneMaintainer<KS, CF>
where
    KS: Deref + Send + Sync + 'static,
    KS::Target: KeyStore,
    <KS::Target as KeyStore>::Key: Clone + Debug + Sync + Send + 'static,
    CF: ConnectionFactory + Send + Sync + 'static,
{
    /// Get a status report for a zone.
    ///
    /// The ZoneMaintainer must be [`run()`]ing for this to work.
    ///
    /// When unable to report the status for a zone the error will be one of
    /// the following:
    ///   - [`CatalogError::NotRunning`]
    ///   - [`CatalogError::UnknownZone`]
    pub async fn zone_status(
        &self,
        apex_name: &StoredName,
        class: Class,
    ) -> Result<ZoneReport, ZoneMaintainerError> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        // If we are unable to send it means that the ZoneMaintainer is not
        // running so cannot respond to the request.
        self.event_tx
            .send(Event::ZoneStatusRequested {
                key: (apex_name.clone(), class),
                tx,
            })
            .await
            .map_err(|_| ZoneMaintainerError::NotRunning)?;

        // If the zone is not known we get a RecvError as the ZoneMaintainer
        // will not send a status report back over the oneshot channel but
        // will just drop the sending end causing the client end to see that
        // the channel has been closed.
        rx.await.map_err(|_| ZoneMaintainerError::UnknownZone)
    }

    pub async fn force_zone_refresh(
        &self,
        apex_name: &StoredName,
        class: Class,
    ) {
        self.event_tx
            .send(Event::ZoneRefreshRequested {
                cause: ZoneRefreshCause::ManualTrigger,
                key: (apex_name.clone(), class),
                at: None,
            })
            .await
            .unwrap();
    }
}

impl<KS, CF: ConnectionFactory> ZoneMaintainer<KS, CF>
where
    KS: Deref,
    KS::Target: KeyStore,
{
    /// Wrap a [`Zone`] so that we get notified when it is modified.
    fn wrap_zone(zone: TypedZone, notify_tx: Sender<Event>) -> Zone {
        let diffs = Arc::new(Mutex::new(ZoneDiffs::new()));
        let nameservers = Arc::new(Mutex::new(None));
        let expired = Arc::new(AtomicBool::new(false));

        let (zone_store, zone_type) = zone.into_inner();

        let zone_info = ZoneInfo {
            _catalog_member_id: None, // TODO
            config: zone_type,
            diffs,
            nameservers,
            expired,
        };

        let new_store = MaintainedZone::new(notify_tx, zone_store, zone_info);
        Zone::new(new_store)
    }
}

impl<KS, CF> ZoneMaintainer<KS, CF>
where
    KS: Deref + 'static,
    KS::Target: KeyStore,
    <KS::Target as KeyStore>::Key:
        Clone + Debug + Display + Sync + Send + 'static,
    CF: ConnectionFactory + 'static,
{
    async fn send_notify(
        zone: &Zone,
        notify: &NotifySrcDstConfig,
        config: Arc<ArcSwap<Config<KS, CF>>>,
    ) {
        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<MaintainedZone>()
            .unwrap();

        let zone_info = cat_zone.info();

        // TODO: Make sending to the notify set configurable
        let locked_nameservers = zone_info.nameservers.lock().await;
        if let Some(nameservers) = locked_nameservers.as_ref() {
            Self::send_notify_to_addrs(
                cat_zone.apex_name().clone(),
                nameservers.notify_set(),
                config.clone(),
                zone_info,
            )
            .await;
        }

        if !notify.is_empty() {
            Self::send_notify_to_addrs(
                cat_zone.apex_name().clone(),
                notify.addrs(),
                config,
                zone_info,
            )
            .await;
        }
    }

    async fn send_notify_to_addrs(
        apex_name: StoredName,
        notify_set: impl Iterator<Item = &SocketAddr>,
        config: Arc<ArcSwap<Config<KS, CF>>>,
        zone_info: &ZoneInfo,
    ) {
        let mut dgram_config = dgram::Config::new();
        dgram_config.set_max_parallel(1);
        dgram_config.set_read_timeout(Duration::from_millis(1000));
        dgram_config.set_max_retries(1);
        dgram_config.set_udp_payload_size(Some(1400));

        let mut msg = MessageBuilder::new_vec();
        msg.header_mut().set_opcode(Opcode::NOTIFY);
        let mut msg = msg.question();
        msg.push((apex_name, Rtype::SOA)).unwrap();

        let loaded_config = config.load();
        let readable_key_store = &loaded_config.key_store;

        for nameserver_addr in notify_set {
            let dgram_config = dgram_config.clone();
            let req = RequestMessage::new(msg.clone()).unwrap();
            let nameserver_addr = *nameserver_addr;

            let tsig_key = zone_info
                .config
                .send_notify_to
                .dst(&nameserver_addr)
                .and_then(|cfg| cfg.tsig_key.as_ref())
                .and_then(|(name, alg)| {
                    readable_key_store.get_key(name, *alg)
                });

            if let Some(key) = tsig_key.as_ref() {
                debug!("Found TSIG key '{}' (algorith {}) for NOTIFY to {nameserver_addr}",
                    key.as_ref().name(), key.as_ref().algorithm());
            }

            tokio::spawn(async move {
                // TODO: Use the connection factory here.
                let udp_connect = UdpConnect::new(nameserver_addr);
                let client = Connection::with_config(
                    udp_connect,
                    dgram_config.clone(),
                );

                trace!("Sending NOTIFY to nameserver {nameserver_addr}");
                let span =
                    tracing::trace_span!("auth", addr = %nameserver_addr);
                let _guard = span.enter();

                // https://datatracker.ietf.org/doc/html/rfc1996
                //   "4.8 Master Receives a NOTIFY Response from Slave
                //
                //    When a master server receives a NOTIFY response, it deletes this
                //    query from the retry queue, thus completing the "notification
                //    process" of "this" RRset change to "that" server."
                //
                // TODO: We have no retry queue at the moment. Do we need one?

                let res = if let Some(key) = tsig_key {
                    let client = net::client::tsig::Connection::new(
                        key.clone(),
                        client,
                    );
                    client.send_request(req.clone()).get_response().await
                } else {
                    client.send_request(req.clone()).get_response().await
                };

                if let Err(err) = res {
                    warn!("Unable to send NOTIFY to nameserver {nameserver_addr}: {err}");
                }
            });
        }
    }

    // Returns the SOA refresh value for the zone, unless the zone is empty.
    // Returns an error if the zone is not a secondary.
    async fn track_zone_freshness(
        zone: &Zone,
        time_tracking: Arc<RwLock<HashMap<ZoneKey, ZoneRefreshState>>>,
    ) -> Result<Option<Ttl>, ()> {
        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<MaintainedZone>()
            .unwrap();

        if !cat_zone.info().config.is_secondary() {
            // TODO: log this? dbg_assert()?
            return Err(());
        }

        let apex_name = zone.apex_name().clone();
        let class = zone.class();
        let key = (apex_name.clone(), class);
        match time_tracking.write().await.entry(key.clone()) {
            Vacant(e) => {
                let read = zone.read();
                if let Ok(Some((soa, _))) =
                    Self::read_soa(&read, apex_name).await
                {
                    e.insert(ZoneRefreshState::new(&soa));
                    Ok(Some(soa.refresh()))
                } else {
                    e.insert(ZoneRefreshState::default());
                    Ok(None)
                }
            }

            Occupied(e) => {
                // Zone is already managed, just return the recorded SOA
                // REFRESH value.
                Ok(Some(e.get().refresh()))
            }
        }
    }

    fn refresh_zone_at(
        cause: ZoneRefreshCause,
        key: ZoneKey,
        at: Option<Ttl>,
        refresh_timers: &mut FuturesUnordered<ZoneRefreshTimer>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc1996#section-4
        // "4.3. If a master server seeks to avoid causing a large number of
        //  simultaneous outbound zone transfers, it may delay for an
        //  arbitrary length of time before sending a NOTIFY message to any
        //  given slave. It is expected that the time will be chosen at
        //  random, so that each slave will begin its transfer at a unique
        //  time.  The delay shall not in any case be longer than the SOA
        //  REFRESH time."
        //
        // TODO: Maybe add some fuzzyness to spread syncing of zones out a
        // bit.

        let new_refresh_instant = ZoneRefreshInstant::new(
            key.clone(),
            at.unwrap_or(Ttl::ZERO),
            cause,
        );

        let new_timer = ZoneRefreshTimer::new(new_refresh_instant);

        // Only add a new timer for a zone if one doesn't already exist for
        // that zone that will fire sooner than the new one. If the new timer
        // would fire earlier than the existing one, update the existing one.
        let timer_for_this_zone = refresh_timers
            .iter_mut()
            .find(|timer| timer.refresh_instant.key == key);

        if let Some(timer) = timer_for_this_zone {
            if timer
                .deadline()
                .checked_duration_since(new_timer.deadline())
                .is_none()
            {
                // This timer is earlier than the new timer, don't add the new
                // one.
                debug!("Skipping creation of later timer");
                return;
            } else {
                // This timer is later or at the same time as the new one.
                debug!("Replacing later timer with new timer");
                timer.replace(new_timer);
                return;
            }
        }

        refresh_timers.push(new_timer);
    }

    #[allow(clippy::mutable_key_type)]
    async fn handle_notify(
        zones: Arc<ZoneTree>,
        pending_zones: Arc<RwLock<HashMap<ZoneKey, Zone>>>,
        msg: ZoneChangedMsg,
        time_tracking: Arc<RwLock<HashMap<ZoneKey, ZoneRefreshState>>>,
        event_tx: Sender<Event>,
        config: Arc<ArcSwap<Config<KS, CF>>>,
    ) {
        // Do we have the zone that is being updated?
        let readable_pending_zones = pending_zones.read().await;
        let mut is_pending = false;
        let zone =
            if let Some(zone) = zones.get_zone(&msg.apex_name, msg.class) {
                zone
            } else if let Some(zone) = readable_pending_zones
                .get(&(msg.apex_name.clone(), msg.class))
            {
                is_pending = true;
                zone
            } else {
                warn!(
                    "Ignoring change notification for unknown zone '{}'.",
                    msg.apex_name
                );
                return;
            };

        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<MaintainedZone>()
            .unwrap();

        // Are we the primary for the zone? We don't accept external
        // notifications for updates to a zone that we are authoritative for.
        let zone_info = cat_zone.info();

        let (source, allow_notify_from) =
            match (msg.source, &zone_info.config) {
                (None, zone_cfg) => {
                    // One of our zones has been changed locally.
                    trace!(
                        "Local change occurred in zone '{}'",
                        msg.apex_name
                    );

                    Self::update_known_nameservers_for_zone(zone).await;
                    Self::send_notify(zone, &zone_cfg.send_notify_to, config)
                        .await;
                    return;
                }

                (Some(source), zone_cfg) => {
                    // A remote notification that a zone that we are secondary for
                    // has been updated on the remote server. If the notification
                    // is legitimate we will want to check if the remote copy of
                    // the zone is indeed newer than our copy and then fetch the
                    // changes.
                    trace!(
                        "Remote change notification received for zone '{}'",
                        msg.apex_name
                    );
                    (source, &zone_cfg.allow_notify_from)
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

        if !Self::is_known_primary(allow_notify_from, &source, zone).await {
            warn!(
                "NOTIFY for {}, from {source}: refused, no acl matches",
                msg.apex_name
            );
            return;
        };

        // https://datatracker.ietf.org/doc/html/rfc1996#section-4
        // "4.3. If a master server seeks to avoid causing a large number of
        //  simultaneous outbound zone transfers, it may delay for an
        //  arbitrary length of time before sending a NOTIFY message to any
        //  given slave. It is expected that the time will be chosen at
        //  random, so that each slave will begin its transfer at a unique
        //  time.  The delay shall not in any case be longer than the SOA
        //  REFRESH time."
        //
        // TODO

        // https://datatracker.ietf.org/doc/html/rfc1996#section-4
        //   "4.7 Slave Receives a NOTIFY Request from a Master
        //
        //    When a slave server receives a NOTIFY request from one of
        //    its locally designated masters for the zone enclosing the
        //    given QNAME, with QTYPE=SOA and QR=0, it should enter the
        //    state it would if the zone's refresh timer had expired."

        let apex_name = zone.apex_name().clone();
        let class = zone.class();
        let key = (apex_name, class);
        let tt = &mut time_tracking.write().await;
        let Some(zone_refresh_info) = tt.get_mut(&key) else {
            // TODO
            warn!(
                "NOTIFY for {}, from {source}: refused, missing internal state",
                msg.apex_name
            );
            return;
        };

        // https://datatracker.ietf.org/doc/html/rfc1996#section-4 "4.4. A
        // slave which receives a valid NOTIFY should defer action on any
        //  subsequent NOTIFY with the same <QNAME,QCLASS,QTYPE> until it has
        //  completed the transaction begun by the first NOTIFY.  This
        //  duplicate rejection is necessary to avoid having multiple
        //  notifications lead to pummeling the master server."
        //
        // We only support the original SOA qtype for NOTIFY. The unique tuple
        // that identifies an in-progress NOTIFY is thus only <QNAME,QCLASS>.
        // This is the same tuple as that of `ZoneKey`, thus we only have one
        // zone for each unique tuple in our set of zones. Thus to avoid
        // processing a NOTIFY when one is already in progress for a unique
        // tuple we only have to look at the status of the zone for which the
        // notify was received.
        if matches!(
            zone_refresh_info.status(),
            ZoneRefreshStatus::NotifyInProgress
        ) {
            // Note: Rather than defer the NOTIFY when one is already in
            // progress we ignore the additional NOTIFY.
            // TODO: Should this be WARN, or DEBUG? Or an incremented metric?
            warn!(
                "NOTIFY for {}, from {source}: refused, notify already in progress for this zone",
                msg.apex_name
            );
            return;
        }

        zone_refresh_info.set_status(ZoneRefreshStatus::NotifyInProgress);

        let initial_xfr_addr = SocketAddr::new(source, IANA_DNS_PORT_NUMBER);
        if let Err(()) = Self::refresh_zone_and_update_state(
            ZoneRefreshCause::NotifyFromPrimary(source),
            zone,
            Some(initial_xfr_addr),
            zone_refresh_info,
            event_tx.clone(),
            config,
        )
        .await
        {
            // TODO
            return;
        }

        // Trigger migration of the zone from the pending set to the active set.
        if is_pending {
            event_tx.send(Event::ZoneAdded(key)).await.unwrap();
        }
    }

    #[allow(clippy::mutable_key_type)]
    async fn refresh_zone_and_update_state(
        cause: ZoneRefreshCause,
        zone: &Zone,
        initial_xfr_addr: Option<SocketAddr>,
        zone_refresh_info: &mut ZoneRefreshState,
        event_tx: Sender<Event>,
        config: Arc<ArcSwap<Config<KS, CF>>>,
    ) -> Result<(), ()> {
        match cause {
            ZoneRefreshCause::ManualTrigger
            | ZoneRefreshCause::NotifyFromPrimary(_)
            | ZoneRefreshCause::SoaRefreshTimer
            | ZoneRefreshCause::SoaRefreshTimerAfterStartup
            | ZoneRefreshCause::SoaRefreshTimerAfterZoneAdded => {
                zone_refresh_info
                    .metrics_mut()
                    .last_refresh_phase_started_at = Some(Instant::now());
                zone_refresh_info.metrics_mut().last_refresh_attempted_at =
                    Some(Instant::now());
            }
            ZoneRefreshCause::SoaRetryTimer => {
                zone_refresh_info.metrics_mut().last_refresh_attempted_at =
                    Some(Instant::now());
            }
        }

        let apex_name = zone.apex_name().clone();
        let class = zone.class();
        let key = (apex_name, class);

        info!("Refreshing zone '{}' due to {cause}", zone.apex_name());

        let res = Self::refresh_zone(
            zone,
            initial_xfr_addr,
            zone_refresh_info,
            config,
        )
        .await;

        match res {
            Err(err) => {
                error!(
                    "Failed to refresh zone '{}': {err}",
                    zone.apex_name()
                );

                // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.5
                // 4.3.5. Zone maintenance and transfers
                //   ..
                //   "Whenever a new zone is loaded in a secondary, the
                //    secondary waits REFRESH seconds before checking with the
                //    primary for a new serial. If this check cannot be
                //    completed, new checks are started every RETRY seconds."
                //   ..
                //   "If the secondary finds it impossible to perform a serial
                //    check for the EXPIRE interval, it must assume that its
                //    copy of the zone is obsolete an discard it."

                if zone_refresh_info.status() == ZoneRefreshStatus::Retrying {
                    let time_of_last_soa_check = zone_refresh_info
                        .metrics()
                        .last_soa_serial_check_succeeded_at
                        .unwrap_or(
                            zone_refresh_info.metrics().zone_created_at,
                        );

                    if zone_refresh_info.is_expired(time_of_last_soa_check) {
                        let cat_zone = zone
                            .as_ref()
                            .as_any()
                            .downcast_ref::<MaintainedZone>()
                            .unwrap();

                        trace!(
                            "Marking zone '{}' as expired",
                            zone.apex_name()
                        );
                        cat_zone.mark_expired();

                        // TODO: Should we keep trying to refresh an
                        // expired zone so that we can bring it back to
                        // life if we are able to connect to the primary?
                        //
                        // https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options
                        // Authority Zone Options
                        //   ...
                        //   "If the update fetch fails, the timers in the
                        //   SOA record are used to time another fetch
                        //   attempt. Until the SOA expiry timer is
                        //   reached. Then the zone is expired. When a
                        //   zone is expired, queries are SERVFAIL, and
                        //   any new serial number is accepted from the
                        //   primary (even if older), and if fallback is
                        //   enabled, the fallback activates to fetch from
                        //   the upstream instead of the SERVFAIL."
                        //
                        // ^^^ Maybe we should do the same as Unbound?

                        return Err(());
                    }
                } else {
                    zone_refresh_info.set_status(ZoneRefreshStatus::Retrying);
                }

                // Schedule a zone refresh according to the SOA RETRY timer value.
                Self::schedule_zone_refresh(
                    ZoneRefreshCause::SoaRetryTimer,
                    &event_tx,
                    key,
                    zone_refresh_info.retry(),
                )
                .await;

                Err(())
            }

            Ok(new_soa) => {
                if let Some(new_soa) = new_soa {
                    // Refresh succeeded:
                    zone_refresh_info.refresh_succeeded(&new_soa);
                } else {
                    // No transfer was required, either because transfer is
                    // not enabled at the primaries for the zone or the zone
                    // is up-to-date with the primaries.
                }

                zone_refresh_info.set_status(ZoneRefreshStatus::Refreshing);

                // Schedule a zone refresh according to the SOA REFRESH timer value.
                Self::schedule_zone_refresh(
                    ZoneRefreshCause::SoaRefreshTimer,
                    &event_tx,
                    key,
                    zone_refresh_info.refresh(),
                )
                .await;

                Ok(())
            }
        }
    }

    async fn refresh_zone(
        zone: &Zone,
        initial_xfr_addr: Option<SocketAddr>,
        zone_refresh_info: &mut ZoneRefreshState,
        config: Arc<ArcSwap<Config<KS, CF>>>,
    ) -> Result<Option<Soa<Name<Bytes>>>, ZoneMaintainerError> {
        // Was this zone already refreshed recently?
        if let Some(age) = zone_refresh_info.age() {
            if age < MIN_DURATION_BETWEEN_ZONE_REFRESHES {
                // Don't refresh, we refreshed very recently
                debug!("Skipping refresh of zone '{}' as it was refreshed less than {}s ago ({}s)",
                    zone.apex_name(), MIN_DURATION_BETWEEN_ZONE_REFRESHES.as_secs(), age.as_secs());
                return Ok(None);
            }
        }

        // Determine which strategy to use if the zone has multiple primaries
        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<MaintainedZone>()
            .unwrap();

        let ZoneConfig {
            multi_primary_xfr_strategy,
            request_xfr_from,
            ..
        } = &cat_zone.info().config;

        // TODO: If we later have more than one MultiPrimaryXfrStrategy,
        // adjust our behaviour to match the requested strategy.
        // TODO: Factor out the multi-primary strategy to a generic type on
        // ZoneMaintainer that implements a trait to make it pluggable.
        assert!(matches!(multi_primary_xfr_strategy, NotifyStrategy::NotifySourceFirstThenSequentialStoppingAtFirstNewerSerial));

        // Determine our current SOA SERIAL value so that we can check that
        // the primary is higher. If the zone is a new secondary it will not
        // have a SOA RR and any available data for the zone available at a
        // primary should be accepted.
        let soa = Self::read_soa(&zone.read(), zone.apex_name().clone())
            .await
            .map_err(|_out_of_zone_err| ZoneMaintainerError::InternalError("Unable to read SOA for zone when checking if zone refresh is needed"))?;

        let current_serial = soa.map(|(soa, _)| soa.serial());

        // Determine the primary server addresses to visit and in which order.
        let primary_addrs =
            initial_xfr_addr.iter().chain(request_xfr_from.addrs());

        let mut num_ok_primaries = 0;
        let mut saved_err = None;

        for primary_addr in primary_addrs {
            if let Some(xfr_config) = request_xfr_from.dst(primary_addr) {
                let res = Self::refresh_zone_from_addr(
                    zone,
                    current_serial,
                    *primary_addr,
                    xfr_config,
                    zone_refresh_info,
                    config.clone(),
                )
                .await;

                match res {
                    Ok(Some(_)) => {
                        // Success!
                        return res;
                    }
                    Ok(None) => {
                        // No transfer supported to this primary or this
                        // primary has equal or older data than we already
                        // have. Try the next primary.
                        num_ok_primaries += 1;
                    }
                    Err(err) => {
                        // Transfer failed. This should already have been
                        // logged along with more details about the transfer
                        // than we have here. Try the next primary.
                        warn!("Refreshing zone '{}' from {primary_addr} failed: {err}", zone.apex_name());
                        saved_err = Some(err);
                    }
                }
            }
        }

        if num_ok_primaries > 0 {
            Ok(None)
        } else {
            Err(saved_err.unwrap())
        }
    }

    async fn refresh_zone_from_addr(
        zone: &Zone,
        current_serial: Option<Serial>,
        primary_addr: SocketAddr,
        xfr_config: &XfrConfig,
        zone_refresh_info: &mut ZoneRefreshState,
        config: Arc<ArcSwap<Config<KS, CF>>>,
    ) -> Result<Option<Soa<Name<Bytes>>>, ZoneMaintainerError> {
        // Build the SOA request message
        let msg = MessageBuilder::new_vec();
        let mut msg = msg.question();
        msg.push((zone.apex_name(), Rtype::SOA)).unwrap();
        let msg = msg.into_message();
        let req = RequestMessage::new(msg).unwrap();

        // https://datatracker.ietf.org/doc/html/rfc5936#section-6
        // 6.  Zone Integrity
        // ...
        //   "Besides best attempts at securing TCP connections, DNS
        //    implementations SHOULD provide means to make use of "Secret Key
        //    Transaction Authentication for DNS (TSIG)" [RFC2845] and/or "DNS
        //    Request and Transaction Signatures ( SIG(0)s )" [RFC2931] to
        //    allow AXFR clients to verify the contents. These techniques MAY
        //    also be used for authorization."
        //
        // When constructing an appropriate DNS client below to query the SOA
        // and to do XFR a TSIG signing/validating "auth" connection is
        // constructed if a key is specified and available.

        let loaded_config = config.load();
        let readable_key_store = &loaded_config.key_store;
        let key = xfr_config
            .tsig_key
            .as_ref()
            .and_then(|(name, alg)| readable_key_store.get_key(name, *alg));

        // Query the SOA serial of the primary.
        let Some(udp_client) = loaded_config
            .conn_factory
            .get_udp(primary_addr, key.clone())
            .await
            .map_err(|err| {
                let key = key.clone().map(|key| format!("{key}")).unwrap_or("NOKEY".to_string());
                ZoneMaintainerError::ConnectionError(format!("Connecting to {primary_addr} via UDP with key '{key}' failed: {err}"))
            })?
        else {
            return Err(ZoneMaintainerError::NoConnectionAvailable);
        };

        trace!(
            "Sending SOA query for zone '{}' to {primary_addr}",
            zone.apex_name()
        );
        let send_request = &mut udp_client.send_request(req);
        let msg = send_request.get_response().await?;

        let primary_soa_serial =
            Self::extract_response_soa_serial(msg).await?;

        let newer_data_available = current_serial
            .map(|v| primary_soa_serial > v)
            .unwrap_or(true);

        debug!("Current: {current_serial:?}");
        debug!("Primary: {primary_soa_serial}");
        debug!("Newer data available: {newer_data_available}");

        if !newer_data_available {
            zone_refresh_info.soa_serial_check_succeeded(None);
            return Ok(None);
        } else {
            zone_refresh_info
                .soa_serial_check_succeeded(Some(primary_soa_serial));
        }

        let mut udp_client = Some(udp_client);

        // TODO: Replace this loop with one, or two, calls to a helper fn?
        // Try at least once, at most twice (when using IXFR -> AXFR fallback)
        for i in 0..=1 {
            // Determine the kind of transfer to use if the zone is outdated
            let rtype = match xfr_config.strategy {
                XfrStrategy::None => {
                    warn!("Transfer not enabled for possibly outdated secondary zone '{}'", zone.apex_name());
                    return Ok(None);
                }
                XfrStrategy::AxfrOnly => Rtype::AXFR,
                XfrStrategy::IxfrOnly => Rtype::IXFR,
                XfrStrategy::IxfrWithAxfrFallback if i == 0 => {
                    // IXFR requires an initial serial number, if we don't
                    // have one yet use AXFR instead.
                    match current_serial {
                        Some(_) => Rtype::IXFR,
                        None => Rtype::AXFR,
                    }
                }
                XfrStrategy::IxfrWithAxfrFallback if i == 1 => {
                    trace!("Falling back to AXFR for primary {primary_addr}");
                    Rtype::AXFR
                }
                _ => break,
            };

            // Fetch the SOA serial using the appropriate transport
            let transport = match rtype {
                Rtype::AXFR => TransportStrategy::Tcp,
                Rtype::IXFR => xfr_config.ixfr_transport,
                _ => unreachable!(),
            };

            if matches!(transport, TransportStrategy::None) {
                // IXFR not allowed by the zone config.
                continue;
            }

            trace!(
                "Refreshing zone '{}' by {rtype} from {primary_addr}",
                zone.apex_name()
            );
            let res = Self::do_xfr(
                udp_client.take(),
                transport,
                zone,
                primary_addr,
                rtype,
                key.clone(),
                config.clone(),
            )
            .await;

            match res {
                Err(ZoneMaintainerError::ResponseError(OptRcode::NOTIMP))
                    if rtype == Rtype::IXFR =>
                {
                    trace!("Primary {primary_addr} doesn't support IXFR");
                    continue;
                }

                Ok(new_soa) => {
                    zone_refresh_info.refresh_succeeded(&new_soa);
                    return Ok(Some(new_soa));
                }

                Err(err) => return Err(err),
            }
        }

        Ok(None)
    }

    /// Does the primary have a newer serial than us?
    ///
    /// Returns Ok(true) if so, Ok(false) if its serial is equal or older, or
    /// Err if the response message indicated an error.
    async fn extract_response_soa_serial(
        msg: Message<Bytes>,
    ) -> Result<Serial, ZoneMaintainerError> {
        if msg.no_error() {
            if let Ok(answer) = msg.answer() {
                let mut records = answer.limit_to::<Soa<_>>();
                let record = records.next();
                if let Some(Ok(record)) = record {
                    return Ok(record.data().serial());
                }
            }
        }

        Err(ZoneMaintainerError::ResponseError(msg.opt_rcode()))
    }

    async fn do_xfr(
        udp_client: Option<
            Box<dyn SendRequest<RequestMessage<Vec<u8>>> + Send + Sync>,
        >,
        transport: TransportStrategy,
        zone: &Zone,
        primary_addr: SocketAddr,
        xfr_type: Rtype,
        key: Option<<<KS as Deref>::Target as KeyStore>::Key>,
        config: Arc<ArcSwap<Config<KS, CF>>>,
    ) -> Result<Soa<Name<Bytes>>, ZoneMaintainerError> {
        // Update the zone from the primary using XFR.
        info!(
            "Zone '{}' is outdated, attempting to sync zone by {xfr_type} from {}",
            zone.apex_name(),
            primary_addr,
        );

        let msg = MessageBuilder::new_vec();
        let mut msg = msg.question();
        msg.push((zone.apex_name(), xfr_type)).unwrap();
        let msg = if xfr_type == Rtype::IXFR {
            let mut msg = msg.authority();
            let read = zone.read();
            let Ok(Some((soa, ttl))) =
                Self::read_soa(&read, zone.apex_name().clone()).await
            else {
                trace!(
                    "Internal error - missing SOA for zone '{}'",
                    zone.apex_name()
                );
                return Err(ZoneMaintainerError::InternalError(
                    "Unable to read SOA for zone when preparing for IXFR in",
                ));
            };
            msg.push((zone.apex_name(), ttl, soa)).unwrap();
            msg
        } else {
            msg.authority()
        };

        let mut xfr_processor = XfrResponseProcessor::new();
        let mut zone_updater = ZoneUpdateEventHandler::new(zone.clone())
            .await
            .map_err(ZoneMaintainerError::IoError)?;

        match transport {
            TransportStrategy::None => unreachable!(),

            TransportStrategy::Udp => {
                // Use the given UDP client if available, else get another one.

                let client = match udp_client {
                    Some(udp_client) => {
                        trace!("Using existing UDP client");
                        udp_client
                    }
                    None => {
                        trace!("Getting UDP client");
                        let loaded_config = config.load();
                        let Some(udp_client) = loaded_config
                            .conn_factory
                            .get_udp(primary_addr, key.clone())
                            .await
                            .map_err(|err| {
                                let key = key.map(|key| format!("{key}")).unwrap_or("NOKEY".to_string());
                                ZoneMaintainerError::ConnectionError(format!("Connecting to {primary_addr} via UDP with key '{key}' failed: {err}"))
                            })?
                        else {
                            return Err(ZoneMaintainerError::NoConnectionAvailable);
                        };
                        udp_client
                    }
                };

                let msg = msg.into_message();
                let req = RequestMessage::new(msg).unwrap();
                let mut send_request = client.send_request(req);
                let msg = send_request
                    .get_response()
                    .await
                    .map_err(ZoneMaintainerError::RequestError)?;

                if msg.is_error() {
                    return Err(ZoneMaintainerError::ResponseError(
                        msg.opt_rcode(),
                    ));
                }

                // TODO: process response, either a complete IXFR or AXFR
                // inside a single UDP packet (which could be a single SOA
                // either indicating that the client is up-to-date, or if
                // newer that the client should fallback to TCP).
                let it = xfr_processor
                    .process_answer(msg)
                    .map_err(ZoneMaintainerError::ProcessingError)?;

                let mut eot = false;

                trace!("Processing XFR events");
                for evt in it {
                    let evt = evt.map_err(|_err| {
                        ZoneMaintainerError::ProcessingError(
                            ProcessingError::Malformed,
                        )
                    })?;

                    eot = matches!(evt, XfrEvent::EndOfTransfer(_));

                    zone_updater
                        .handle_event(evt)
                        .await
                        .map_err(|()| ZoneMaintainerError::ZoneUpdateError)?;

                    if eot {
                        break;
                    }
                }

                if !eot {
                    trace!(
                        "Processing XFR events complete: incomplete response"
                    );
                    return Err(ZoneMaintainerError::IncompleteResponse);
                }

                trace!("Processing XFR events complete");
            }

            TransportStrategy::Tcp => {
                // Get a TCP connection.
                trace!("Getting TCP client");
                let loaded_config = config.load();
                let Some(tcp_client) = loaded_config
                    .conn_factory
                    .get_tcp(primary_addr, key.clone())
                    .await
                    .map_err(|err| {
                        let key = key.map(|key| format!("{key}")).unwrap_or("NOKEY".to_string());
                        ZoneMaintainerError::ConnectionError(format!("Connecting to {primary_addr} via TCP with key '{key}' failed: {err}"))
                    })?
                else {
                    return Err(ZoneMaintainerError::NoConnectionAvailable);
                };

                let msg = msg.into_message();
                let req = RequestMessageMulti::new(msg).unwrap();
                let mut send_request = tcp_client.send_request(req);

                trace!("Fetching XFR responses");
                'outer: loop {
                    trace!("Fetching XFR response");
                    let msg = send_request
                        .get_response()
                        .await
                        .map_err(ZoneMaintainerError::RequestError)?;

                    let Some(msg) = msg else {
                        return Err(ZoneMaintainerError::IncompleteResponse);
                    };

                    if msg.is_error() {
                        return Err(ZoneMaintainerError::ResponseError(
                            msg.opt_rcode(),
                        ));
                    }

                    let it = xfr_processor
                        .process_answer(msg)
                        .map_err(ZoneMaintainerError::ProcessingError)?;

                    trace!("Processing XFR events");

                    for evt in it {
                        let evt = evt.map_err(|_err| {
                            ZoneMaintainerError::ProcessingError(
                                ProcessingError::Malformed,
                            )
                        })?;

                        let eot = matches!(evt, XfrEvent::EndOfTransfer(_));

                        zone_updater.handle_event(evt).await.map_err(
                            |()| {
                                error!("Zone update error");
                                ZoneMaintainerError::ZoneUpdateError
                            },
                        )?;

                        if eot {
                            trace!("Processing XFR events: EoT detected");
                            break 'outer;
                        }
                    }

                    trace!("Processing XFR events complete");
                }

                trace!("Fetching XFR responses complete");
            }
        }

        let soa_and_ttl =
            Self::read_soa(&zone.read(), zone.apex_name().clone())
                .await
                .map_err(|_out_of_zone_err| {
                    ZoneMaintainerError::InternalError(
                        "Unable to read SOA for zone post XFR in",
                    )
                })?;

        let Some((soa, _ttl)) = soa_and_ttl else {
            return Err(ZoneMaintainerError::InternalError(
                "SOA for zone missing post XFR in",
            ));
        };

        Ok(soa)
    }

    #[allow(clippy::borrowed_box)]
    async fn read_soa(
        read: &Box<dyn ReadableZone>,
        qname: Name<Bytes>,
    ) -> Result<Option<(Soa<Name<Bytes>>, Ttl)>, OutOfZone> {
        let answer = match read.is_async() {
            true => read.query_async(qname, Rtype::SOA).await,
            false => read.query(qname, Rtype::SOA),
        }?;

        if let AnswerContent::Data(rrset) = answer.content() {
            if let ZoneRecordData::Soa(soa) = rrset.first().unwrap().data() {
                return Ok(Some((soa.clone(), rrset.ttl())));
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

    // TODO: Review feedback directed to remove this notify set discovery
    // logic entirely and only support a user configured "notify set" rather
    // than the set of servers discovered in the zone by this code.
    //
    // Possibly related:
    //
    // https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#server-options
    // Server Options
    //   ...
    //   "target-fetch-policy: <list of numbers>
    //    Set the target fetch policy used by Unbound to determine if it
    //    should fetch nameserver target addresses opportunistically. The
    //    policy is described per dependency depth.
    //
    //    The number of values determines the maximum dependency depth that
    //    Unbound will pursue in answering a query. A value of -1 means to
    //    fetch all targets opportunistically for that dependency depth. A
    //    value of 0 means to fetch on demand only. A positive value fetches
    //    that many targets opportunistically.
    //
    //    Enclose the list between quotes ("") and put spaces between numbers.
    //    Setting all zeroes, “0 0 0 0 0” gives behaviour closer to that of
    //    BIND 9, while setting “-1 -1 -1 -1 -1” gives behaviour rumoured to
    //    be closer to that of BIND 8.
    //
    //    Default: “3 2 1 0 0”
    async fn identify_nameservers(
        zone: &Zone,
    ) -> Result<ZoneNameServers, ()> {
        trace!(
            "Identifying primary nameservers for zone '{}'",
            zone.apex_name()
        );

        let read = zone.read();

        let Some((soa, _)) = Self::read_soa(&read, zone.apex_name().clone())
            .await
            .map_err(|_| ())?
        else {
            error!(
                "Unable to read SOA RRSET for zone '{}'.",
                zone.apex_name()
            );
            return Err(());
        };

        let mut primary_addresses: Vec<IpAddr> = vec![];

        if let Some(res) =
            Self::read_rrset(&read, soa.mname().clone(), Rtype::A)
                .await
                .map_err(|_| ())?
        {
            for rrset in res.data().iter() {
                if let ZoneRecordData::A(a) = rrset {
                    primary_addresses.push(a.addr().into());
                }
            }
        }

        if let Some(res) =
            Self::read_rrset(&read, soa.mname().clone(), Rtype::AAAA)
                .await
                .map_err(|_| ())?
        {
            for rrset in res.data().iter() {
                if let ZoneRecordData::Aaaa(aaaa) = rrset {
                    primary_addresses.push(aaaa.addr().into());
                }
            }
        }

        let mut nameservers =
            ZoneNameServers::new(soa.mname().clone(), &primary_addresses);

        // Does the zone apex have NS records and are their
        // addresses defined in the zone?
        if let Some(res) =
            Self::read_rrset(&read, zone.apex_name().clone(), Rtype::NS)
                .await
                .map_err(|_| ())?
        {
            let mut data_iter = res.data().iter();
            while let Some(ZoneRecordData::Ns(ns)) = data_iter.next() {
                let mut other_addresses = vec![];

                if let Some(res) =
                    Self::read_rrset(&read, ns.nsdname().clone(), Rtype::A)
                        .await
                        .map_err(|_| ())?
                {
                    for rrset in res.data().iter() {
                        if let ZoneRecordData::A(a) = rrset {
                            other_addresses.push(a.addr().into());
                        }
                    }
                }

                if let Some(res) =
                    Self::read_rrset(&read, ns.nsdname().clone(), Rtype::AAAA)
                        .await
                        .map_err(|_| ())?
                {
                    for rrset in res.data().iter() {
                        if let ZoneRecordData::Aaaa(aaaa) = rrset {
                            other_addresses.push(aaaa.addr().into());
                        }
                    }
                }

                nameservers.add_ns(ns.nsdname().clone(), &other_addresses);
            }
        }

        Ok(nameservers)
    }

    async fn is_known_primary<'a>(
        acl: &'a NotifySrcDstConfig,
        source: &IpAddr,
        zone: &Zone,
    ) -> bool {
        let source_addr = SocketAddr::new(*source, IANA_DNS_PORT_NUMBER);
        if acl.has_dst(&source_addr) {
            trace!("Source IP {source} is on the ACL for the zone.");
            return true;
        } else {
            trace!("Source IP {source} is NOT on the ACL for the zone.");
        }

        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<MaintainedZone>()
            .unwrap();

        if !cat_zone.info().config.discover_notify_set {
            return false;
        }

        let mut locked_nameservers = cat_zone.info().nameservers.lock().await;
        if locked_nameservers.is_none() {
            if let Ok(nameservers) = Self::identify_nameservers(zone).await {
                *locked_nameservers = Some(nameservers);
            } else {
                return false;
            }
        }

        let nameservers = locked_nameservers.as_ref().unwrap();
        let source_addr = SocketAddr::new(*source, IANA_DNS_PORT_NUMBER);

        if nameservers.primary.1.contains(&source_addr) {
            trace!("Source IP {source} matches primary nameserver '{}' ({source}) for zone '{}'.", nameservers.primary.0, zone.apex_name());
            return true;
        }

        let res = nameservers
            .other
            .iter()
            .find(|(_name, ips)| ips.contains(&source_addr));

        if let Some((name, _)) = res {
            trace!("Source IP {source} matches nameserver '{name}' ({source}) for zone '{}'.", zone.apex_name());
            true
        } else {
            trace!("Source IP {source} does NOT match any primary name servers for zone '{}'.", zone.apex_name());
            false
        }
    }

    async fn schedule_zone_refresh(
        cause: ZoneRefreshCause,
        event_tx: &Sender<Event>,
        key: ZoneKey,
        at: Ttl,
    ) {
        event_tx
            .send(Event::ZoneRefreshRequested {
                cause,
                key,
                at: Some(at),
            })
            .await
            .unwrap();
    }

    async fn update_known_nameservers_for_zone(zone: &Zone) {
        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<MaintainedZone>()
            .unwrap();

        if cat_zone.info().config.discover_notify_set {
            if let Ok(nameservers) = Self::identify_nameservers(zone).await {
                *cat_zone.info().nameservers.lock().await = Some(nameservers);
            };
        }
    }
}

//--- Notifiable

impl<KS, CF> Notifiable for ZoneMaintainer<KS, CF>
where
    KS: Deref + Send + Sync + 'static,
    KS::Target: KeyStore,
    CF: ConnectionFactory + Send + Sync + 'static,
{
    #[allow(clippy::manual_async_fn)]
    fn notify_zone_changed(
        &self,
        class: Class,
        apex_name: &StoredName,
        source: IpAddr,
    ) -> Pin<
        Box<dyn Future<Output = Result<(), NotifyError>> + Sync + Send + '_>,
    > {
        let apex_name = apex_name.clone();
        Box::pin(async move {
            if !self.running.load(Ordering::SeqCst) {
                return Err(NotifyError::Other);
            }

            if self.zones().get_zone(&apex_name, class).is_none() {
                let key = (apex_name.clone(), class);
                if !self.pending_zones.read().await.contains_key(&key) {
                    return Err(NotifyError::NotAuthForZone);
                }
            }

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
            // quick so we leave that to the running ZoneMaintainer task to handle.

            let msg = ZoneChangedMsg {
                class,
                apex_name: apex_name.clone(),
                source: Some(source),
            };

            self.event_tx.send(Event::ZoneChanged(msg)).await.map_err(
                |err| {
                    error!("Internal error: {err}");
                    NotifyError::Other
                },
            )?;

            Ok(())
        })
    }
}

impl<KS, CF: ConnectionFactory> ZoneMaintainer<KS, CF>
where
    KS: Deref,
    KS::Target: KeyStore,
{
    fn update_lodaded_arc(&self) {
        *self.loaded_arc.write().unwrap() = self.member_zones.load_full();
    }
}

//--- ZoneLookup

impl<KS, CF: ConnectionFactory> ZoneLookup for ZoneMaintainer<KS, CF>
where
    KS: Deref,
    KS::Target: KeyStore,
{
    /// The entire tree of zones managed by this [`ZoneMaintainer`] instance.
    fn zones(&self) -> Arc<ZoneTree> {
        self.loaded_arc.read().unwrap().clone()
    }

    /// The set of "active" zones managed by this [`ZoneMaintainer`] instance.
    ///
    /// Attempting to get a newly added empty secondary zone that is still
    /// pending initial refresh or an expired zone will result in an error.
    /// This allows the caller to distinguish between the ZoneMaintainer not
    /// being authoratitive for a zone (Ok(None)) (thus the response should be
    /// NOTAUTH), a zone for which the ZoneMaintainer is authoritative but is
    /// temporarily not in the correct state (SERVFAIL) vs a zone for which
    /// the ZoneMaintainer is authoritative and which is in the correct state
    /// (Ok).
    fn get_zone(
        &self,
        apex_name: &impl ToName,
        class: Class,
    ) -> Result<Option<Zone>, ZoneError> {
        let zones = self.zones();

        if let Some(zone) = zones.get_zone(apex_name, class) {
            let cat_zone = zone
                .as_ref()
                .as_any()
                .downcast_ref::<MaintainedZone>()
                .unwrap();

            if cat_zone.is_active() {
                return Ok(Some(zone.clone()));
            } else {
                return Err(ZoneError::TemporarilyUnavailable);
            }
        }

        Ok(None)
    }

    /// Gets the closest matching "active" [`Zone`] for the given QNAME and
    /// CLASS, if any.
    ///
    /// Returns the same result as [get_zone()].
    fn find_zone(
        &self,
        qname: &impl ToName,
        class: Class,
    ) -> Result<Option<Zone>, ZoneError> {
        let zones = self.zones();

        if let Some(zone) = zones.find_zone(qname, class) {
            let cat_zone = zone
                .as_ref()
                .as_any()
                .downcast_ref::<MaintainedZone>()
                .unwrap();

            if cat_zone.is_active() {
                return Ok(Some(zone.clone()));
            } else {
                return Err(ZoneError::TemporarilyUnavailable);
            }
        }

        Ok(None)
    }
}

impl<KS, CF> ZoneMaintainer<KS, CF>
where
    KS: Deref + 'static + Sync + Send,
    KS::Target: KeyStore,
    <KS::Target as KeyStore>::Key:
        Clone + Debug + Display + Sync + Send + 'static,
    CF: ConnectionFactory + Sync + Send + 'static,
{
    fn check_xfr_access<'a>(
        zone_info: &'a ZoneInfo,
        zone: &Zone,
        client_ip: IpAddr,
        qtype: Rtype,
    ) -> Result<&'a XfrConfig, XfrDataProviderError> {
        if zone_info.config().provide_xfr_to.is_empty() {
            warn!(
                "{qtype} for zone '{}' from {client_ip} refused: zone does not allow XFR", zone.apex_name(),
            );
            return Err(XfrDataProviderError::Refused);
        };
        let Some(xfr_config) =
            zone_info.config().provide_xfr_to.src(client_ip)
        else {
            warn!(
                "{qtype} for zone '{}' from {client_ip} refused: client is not permitted to transfer this zone", zone.apex_name(),
            );
            return Err(XfrDataProviderError::Refused);
        };

        if matches!(
            (qtype, xfr_config.strategy),
            (Rtype::AXFR, XfrStrategy::IxfrOnly)
                | (Rtype::IXFR, XfrStrategy::AxfrOnly)
        ) {
            warn!(
                "{qtype} for zone '{}' from {client_ip} refused: zone does not allow {qtype}", zone.apex_name(),
            );
            return Err(XfrDataProviderError::Refused);
        }

        Ok(xfr_config)
    }

    async fn diffs_for_zone(
        diff_from: Option<Serial>,
        zone: &Zone,
        zone_info: &ZoneInfo,
    ) -> Vec<Arc<ZoneDiff>>
    where
        KS: Deref + 'static + Sync + Send,
        CF: ConnectionFactory + Sync + Send + 'static,
    {
        let mut diffs = vec![];

        if let Some(diff_from) = diff_from {
            let read = zone.read();
            if let Ok(Some((soa, _ttl))) = ZoneMaintainer::<KS, CF>::read_soa(
                &read,
                zone.apex_name().to_owned(),
            )
            .await
            {
                diffs =
                    zone_info.diffs_for_range(diff_from, soa.serial()).await;
            }
        }

        diffs
    }
}

//--- XfrDataProvider

impl<KS, CF> XfrDataProvider for ZoneMaintainer<KS, CF>
where
    KS: Deref + 'static + Sync + Send,
    KS::Target: KeyStore,
    <KS::Target as KeyStore>::Key:
        Clone + Debug + Display + Sync + Send + 'static,
    CF: ConnectionFactory + Sync + Send + 'static,
{
    fn request<Octs>(
        &self,
        req: &Request<Octs>,
        diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (Zone, Vec<Arc<ZoneDiff>>),
                        net::server::middleware::xfr::XfrDataProviderError,
                    >,
                > + Sync
                + Send
                + '_,
        >,
    >
    where
        Octs: Octets + Send + Sync,
    {
        let opt = if let Ok(q) = req.message().sole_question() {
            Some((self.find_zone(&q.qname(), q.qclass()), q.qtype()))
        } else {
            None
        };

        let client_ip = req.client_addr().ip();

        let res = async move {
            let Some((zone_res, qtype)) = opt else {
                return Err(XfrDataProviderError::Refused);
            };

            match zone_res {
                Ok(Some(zone)) => {
                    let cat_zone = zone
                        .as_ref()
                        .as_any()
                        .downcast_ref::<MaintainedZone>()
                        .unwrap();

                    let zone_info = cat_zone.info();

                    let _ = ZoneMaintainer::<KS, CF>::check_xfr_access(
                        zone_info, &zone, client_ip, qtype,
                    )?;

                    let diffs = ZoneMaintainer::<KS, CF>::diffs_for_zone(
                        diff_from, &zone, zone_info,
                    )
                    .await;

                    Ok((zone.clone(), diffs))
                }

                Ok(None) => Err(XfrDataProviderError::UnknownZone),

                Err(ZoneError::TemporarilyUnavailable) => {
                    Err(XfrDataProviderError::TemporarilyUnavailable)
                }
            }
        };

        Box::pin(res)
    }
}

//--- XfrDataProvider<Authentication>

impl<KS, CF> XfrDataProvider<Authentication> for ZoneMaintainer<KS, CF>
where
    KS: Deref + 'static + Sync + Send,
    KS::Target: KeyStore,
    <KS::Target as KeyStore>::Key:
        Clone + Debug + Display + Sync + Send + 'static,
    CF: ConnectionFactory + Sync + Send + 'static,
{
    fn request<Octs>(
        &self,
        req: &Request<Octs, Authentication>,
        diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (Zone, Vec<Arc<ZoneDiff>>),
                        net::server::middleware::xfr::XfrDataProviderError,
                    >,
                > + Sync
                + Send
                + '_,
        >,
    >
    where
        Octs: Octets + Send + Sync,
    {
        let opt = if let Ok(q) = req.message().sole_question() {
            Some((self.find_zone(&q.qname(), q.qclass()), q.qtype()))
        } else {
            None
        };

        let client_ip = req.client_addr().ip();
        let key_name = req.metadata().key_name().map(ToOwned::to_owned);

        let res = async move {
            let Some((zone_res, qtype)) = opt else {
                return Err(XfrDataProviderError::Refused);
            };

            match zone_res {
                Ok(Some(zone)) => {
                    let cat_zone = zone
                        .as_ref()
                        .as_any()
                        .downcast_ref::<MaintainedZone>()
                        .unwrap();

                    let zone_info = cat_zone.info();

                    let xfr_config =
                        ZoneMaintainer::<KS, CF>::check_xfr_access(
                            zone_info, &zone, client_ip, qtype,
                        )?;

                    let expected_tsig_key_name =
                        xfr_config.tsig_key.as_ref().map(|(name, _alg)| name);
                    let tsig_key_mismatch = match (expected_tsig_key_name, key_name.as_ref()) {
                        (None, Some(actual)) => {
                            Some(format!(
                                "Request was signed with TSIG key '{actual}' but should be unsigned."))
                        }
                        (Some(expected), None) => {
                            Some(
                                format!("Request should be signed with TSIG key '{expected}' but was unsigned"))
                        }
                        (Some(expected), Some(actual)) if *actual != expected => {
                            Some(format!(
                                "Request should be signed with TSIG key '{expected}' but was instead signed with TSIG key '{actual}'"))
                        }
                        (Some(expected), Some(_)) => {
                            trace!("Request is signed with expected TSIG key '{expected}'");
                            None
                        },
                        (None, None) => {
                            trace!("Request is unsigned as expected");
                            None
                        }
                    };
                    if let Some(reason) = tsig_key_mismatch {
                        warn!(
                            "{qtype} for zone '{}' from {client_ip} refused: {reason}",
                            zone.apex_name(),
                        );
                        return Err(XfrDataProviderError::Refused);
                    }

                    let diffs = ZoneMaintainer::<KS, CF>::diffs_for_zone(
                        diff_from, &zone, zone_info,
                    )
                    .await;

                    Ok((zone.clone(), diffs))
                }

                Ok(None) => Err(XfrDataProviderError::UnknownZone),

                Err(ZoneError::TemporarilyUnavailable) => {
                    Err(XfrDataProviderError::TemporarilyUnavailable)
                }
            }
        };

        Box::pin(res)
    }
}

//------------ TypedZone -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct TypedZone {
    store: Arc<dyn ZoneStore>,
    zone_type: ZoneConfig,
}

impl TypedZone {
    pub fn new(zone: Zone, zone_type: ZoneConfig) -> TypedZone {
        TypedZone {
            store: zone.into_inner(),
            zone_type,
        }
    }
    pub fn into_inner(self) -> (Arc<dyn ZoneStore>, ZoneConfig) {
        (self.store, self.zone_type)
    }

    pub fn zone_type(&self) -> &ZoneConfig {
        &self.zone_type
    }
}

impl ZoneStore for TypedZone {
    fn class(&self) -> Class {
        self.store.class()
    }

    fn apex_name(&self) -> &StoredName {
        self.store.apex_name()
    }

    fn read(self: Arc<Self>) -> Box<dyn ReadableZone> {
        self.store.clone().read()
    }

    fn write(
        self: Arc<Self>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>> + Send + Sync>>
    {
        self.store.clone().write()
    }

    fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }
}

//------------ CatalogZone ---------------------------------------------------

#[derive(Debug)]
pub struct MaintainedZone {
    notify_tx: Sender<Event>,
    store: Arc<dyn ZoneStore>,
    info: ZoneInfo,
}

impl MaintainedZone {
    fn new(
        notify_tx: Sender<Event>,
        store: Arc<dyn ZoneStore>,
        info: ZoneInfo,
    ) -> Self {
        Self {
            notify_tx,
            store,
            info,
        }
    }

    fn is_active(&self) -> bool {
        !self.info.expired()
    }

    fn mark_expired(&self) {
        self.info.set_expired(true);
    }
}

impl MaintainedZone {
    pub fn info(&self) -> &ZoneInfo {
        &self.info
    }
}

impl ZoneStore for MaintainedZone {
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
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>> + Send + Sync>>
    {
        let fut = self.store.clone().write();
        let notify_tx = self.notify_tx.clone();
        Box::pin(async move {
            let writable_zone = fut.await;
            let writable_zone = WritableMaintainedZone {
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

struct WritableMaintainedZone {
    catalog_zone: Arc<MaintainedZone>,
    notify_tx: Sender<Event>,
    writable_zone: Box<dyn WritableZone>,
}

impl WritableZone for WritableMaintainedZone {
    fn open(
        &self,
        _create_diff: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        self.writable_zone.open(true)
    }

    fn commit(
        &mut self,
        bump_soa_serial: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<ZoneDiff>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        let fut = self.writable_zone.commit(bump_soa_serial);
        let notify_tx = self.notify_tx.clone();
        let cat_zone = self.catalog_zone.clone();
        Box::pin(async move {
            match fut.await {
                Ok(diff) => {
                    if let Some(diff) = &diff {
                        trace!("Captured diff: {diff:#?}");
                        cat_zone.info().add_diff(diff.clone()).await;
                    }

                    let msg = ZoneChangedMsg {
                        class: cat_zone.class(),
                        apex_name: cat_zone.apex_name().clone(),
                        source: None,
                    };

                    notify_tx.send(Event::ZoneChanged(msg)).await.unwrap(); // TODO

                    Ok(diff)
                }
                Err(err) => Err(err),
            }
        })
    }
}

//------------ CatalogError --------------------------------------------------

#[derive(Debug)]
pub enum ZoneMaintainerError {
    NotRunning,
    InternalError(&'static str),
    UnknownZone,
    RequestError(request::Error),
    ResponseError(OptRcode),
    IoError(io::Error),
    ConnectionError(String),
    NoConnectionAvailable,
    IxfrResponseTooLargeForUdp,
    IncompleteResponse,
    ProcessingError(ProcessingError),
    ZoneUpdateError,
}

//--- Display

impl Display for ZoneMaintainerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneMaintainerError::NotRunning => {
                f.write_str("ZoneMaintainer not running")
            }
            ZoneMaintainerError::InternalError(err) => {
                f.write_fmt(format_args!("Internal error: {err}"))
            }
            ZoneMaintainerError::UnknownZone => f.write_str("Unknown zone"),
            ZoneMaintainerError::RequestError(err) => f.write_fmt(
                format_args!("Error while sending request: {err}"),
            ),
            ZoneMaintainerError::ResponseError(err) => f.write_fmt(
                format_args!("Error while receiving response: {err}"),
            ),
            ZoneMaintainerError::IoError(err) => {
                f.write_fmt(format_args!("I/O error: {err}"))
            }
            ZoneMaintainerError::ConnectionError(err) => {
                f.write_fmt(format_args!("Unable to connect: {err}"))
            }
            ZoneMaintainerError::NoConnectionAvailable => {
                f.write_str("No connection available")
            }
            ZoneMaintainerError::IxfrResponseTooLargeForUdp => {
                f.write_str("IXFR response too large for UDP")
            }
            ZoneMaintainerError::IncompleteResponse => {
                f.write_str("Incomplete response")
            }
            ZoneMaintainerError::ProcessingError(err) => {
                f.write_fmt(format_args!("Processing error: {err}"))
            }
            ZoneMaintainerError::ZoneUpdateError => {
                f.write_str("Zone update error")
            }
        }
    }
}

//--- From request::Error

impl From<request::Error> for ZoneMaintainerError {
    fn from(err: request::Error) -> Self {
        Self::RequestError(err)
    }
}

//--- From io::Error

impl From<io::Error> for ZoneMaintainerError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

//------------ DefaultConnFactory ------------------------------------------

#[derive(Clone, Default)]
pub struct DefaultConnFactory;

//--- ConnectionFactory

impl ConnectionFactory for DefaultConnFactory {
    type Error = String;

    fn get_udp<K, Octs>(
        &self,
        dest: SocketAddr,
        key: Option<K>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<
                            Box<
                                dyn SendRequest<RequestMessage<Octs>>
                                    + Send
                                    + Sync
                                    + 'static,
                            >,
                        >,
                        Self::Error,
                    >,
                > + Send
                + Sync
                + 'static,
        >,
    >
    where
        K: Clone + Debug + AsRef<Key> + Send + Sync + 'static,
        Octs: Octets + Debug + Send + Sync + 'static,
    {
        let fut = async move {
            let mut dgram_config = dgram::Config::new();
            dgram_config.set_max_parallel(1);
            dgram_config.set_read_timeout(Duration::from_millis(1000));
            dgram_config.set_max_retries(1);
            dgram_config.set_udp_payload_size(Some(1400));

            let client = dgram::Connection::with_config(
                UdpConnect::new(dest),
                dgram_config,
            );

            if let Some(key) = key {
                Ok(Some(Box::new(net::client::tsig::Connection::new(
                    key, client,
                ))
                    as Box<
                        dyn SendRequest<RequestMessage<Octs>> + Send + Sync,
                    >))
            } else {
                Ok(Some(Box::new(client)
                    as Box<
                        dyn SendRequest<RequestMessage<Octs>> + Send + Sync,
                    >))
            }
        };

        Box::pin(fut)
    }

    fn get_tcp<K, Octs>(
        &self,
        dest: SocketAddr,
        key: Option<K>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<
                            Box<
                                dyn SendRequestMulti<
                                        RequestMessageMulti<Octs>,
                                    > + Send
                                    + Sync
                                    + 'static,
                            >,
                        >,
                        Self::Error,
                    >,
                > + Send
                + Sync
                + 'static,
        >,
    >
    where
        K: Clone + Debug + AsRef<Key> + Send + Sync + 'static,
        Octs: Octets + Debug + Send + Sync + 'static,
    {
        let fut = async move {
            let mut stream_config = net::client::stream::Config::new();
            stream_config.set_response_timeout(Duration::from_secs(2));
            // Allow time between the SOA query response and sending the
            // AXFR/IXFR request.
            stream_config.set_idle_timeout(Duration::from_secs(5));
            // Allow much more time for an XFR streaming response.
            stream_config
                .set_streaming_response_timeout(Duration::from_secs(30));

            let tcp_stream = TcpStream::connect(dest)
                .await
                .map_err(|err| format!("{err}"))?;

            if let Some(key) = key {
                let (client, transport) = net::client::stream::Connection::<
                    AuthenticatedRequestMessage<RequestMessage<Octs>, K>,
                    AuthenticatedRequestMessage<RequestMessageMulti<Octs>, K>,
                >::with_config(
                    tcp_stream, stream_config
                );

                tokio::spawn(async move {
                    transport.run().await;
                    trace!("TCP connection terminated");
                });

                let conn = net::client::tsig::Connection::new(key, client);
                Ok(Some(Box::new(conn)
                    as Box<
                        dyn SendRequestMulti<RequestMessageMulti<Octs>>
                            + Send
                            + Sync,
                    >))
            } else {
                let (client, transport) = net::client::stream::Connection::<
                    RequestMessage<Octs>,
                    RequestMessageMulti<Octs>,
                >::with_config(
                    tcp_stream, stream_config
                );

                tokio::spawn(async move {
                    transport.run().await;
                    trace!("TCP connection terminated");
                });

                Ok(Some(Box::new(client)
                    as Box<
                        dyn SendRequestMulti<RequestMessageMulti<Octs>>
                            + Send
                            + Sync,
                    >))
            }
        };

        Box::pin(fut)
    }
}

impl<T: SendRequest<RequestMessage<Octs>> + ?Sized, Octs: Octets>
    SendRequest<RequestMessage<Octs>> for Box<T>
{
    fn send_request(
        &self,
        request_msg: RequestMessage<Octs>,
    ) -> Box<dyn request::GetResponse + Send + Sync> {
        (**self).send_request(request_msg)
    }
}

//------------ ZoneLookup -----------------------------------------------------

pub trait ZoneLookup {
    fn zones(&self) -> Arc<ZoneTree>;

    fn get_zone(
        &self,
        apex_name: &impl ToName,
        class: Class,
    ) -> Result<Option<Zone>, ZoneError>;

    fn find_zone(
        &self,
        qname: &impl ToName,
        class: Class,
    ) -> Result<Option<Zone>, ZoneError>;
}

impl<T: ZoneLookup> ZoneLookup for Arc<T> {
    fn zones(&self) -> Arc<ZoneTree> {
        (**self).zones()
    }

    fn get_zone(
        &self,
        apex_name: &impl ToName,
        class: Class,
    ) -> Result<Option<Zone>, ZoneError> {
        (**self).get_zone(apex_name, class)
    }

    fn find_zone(
        &self,
        qname: &impl ToName,
        class: Class,
    ) -> Result<Option<Zone>, ZoneError> {
        (**self).find_zone(qname, class)
    }
}

//------------ ZoneError ------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ZoneError {
    TemporarilyUnavailable,
}
