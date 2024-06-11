// Note to self: This design ties XFR and catalogs together, but really they
// are separate things. Maybe better have triggers/callbacks or something for
// joining separate pieces together, including the XFR-in XfrMiddlewareService
// functionality?
// TODO: Add IXFR diff purging.
// TODO: Add IXFR diff condensation.
// TODO: Add NOTIFY sending based on configured "stealth" nameservers per
// zone.
// TODO: Add NOTIFY set discovery.
// TODO: Add NOTIFY sending to the discovered NOTIFY set.
// TODO: Add lifecycle hooks for callers, e.g. zone added, zone removed, zone
// expired, zone refreshed.
use core::any::Any;
use core::fmt::Debug;
use core::net::{IpAddr, SocketAddr};
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;

use std::borrow::ToOwned;
use std::boxed::Box;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::io;
use std::string::ToString;
use std::sync::Arc;
use std::vec::Vec;

use arc_swap::ArcSwap;
use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::FutureExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{sleep_until, Instant, Sleep};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, trace, warn};

use crate::base::iana::{Class, Opcode, OptRcode};
use crate::base::name::{FlattenInto, Label, ToLabelIter};
use crate::base::{
    CanonicalOrd, Message, MessageBuilder, Name, Rtype, Serial, ToName, Ttl,
};
use crate::net::client::auth::AuthenticatedRequestMessage;
use crate::net::client::dgram::{self, Connection};
use crate::net::client::protocol::UdpConnect;
use crate::net::client::request::{
    self, ComposeRequest, RequestMessage, SendRequest,
};
use crate::net::client::{auth, stream};
use crate::rdata::{Soa, ZoneRecordData};
use crate::tsig::{self, Algorithm, Key, KeyName};
use crate::zonetree::error::{OutOfZone, ZoneTreeModificationError};
use crate::zonetree::{
    AnswerContent, ReadableZone, Rrset, SharedRrset, StoredName,
    WritableZone, WritableZoneNode, Zone, ZoneDiff, ZoneKey, ZoneStore,
    ZoneTree,
};

//------------ Config --------------------------------------------------------

#[derive(Debug, Default)]
pub struct Config {
    key_store: Arc<RwLock<CatalogKeyStore>>,
}

impl Config {
    pub fn new(key_store: Arc<RwLock<CatalogKeyStore>>) -> Self {
        Self { key_store }
    }
}

//------------ Constants -----------------------------------------------------

const IANA_DNS_PORT_NUMBER: u16 = 53;

// TODO: This should be configurable.
const MIN_DURATION_BETWEEN_ZONE_REFRESHES: tokio::time::Duration =
    tokio::time::Duration::new(0, 0);

//------------ Type Aliases --------------------------------------------------

pub type CatalogKeyStore = HashMap<(KeyName, Algorithm), Arc<Key>>;

//------------ Acl -----------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct Acl<T: Clone + Debug + Default> {
    entries: HashMap<SocketAddr, T>,
}

impl<T: Clone + Debug + Default> Acl<T> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn allow_from(&mut self, addr: IpAddr, v: T) {
        let k = SocketAddr::new(addr, IANA_DNS_PORT_NUMBER);
        let _ = self.entries.insert(k, v);
    }

    pub fn allow_to(&mut self, addr: SocketAddr, v: T) {
        let _ = self.entries.insert(addr, v);
    }

    pub fn addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.entries.keys()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<&T> {
        self.entries.get(addr)
    }

    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.entries.contains_key(addr)
    }
}

//------------ XfrStrategy ---------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub enum XfrStrategy {
    #[default]
    None,
    AxfrOnly,
    IxfrOnly,
    IxfrWithAxfrFallback,
}

//------------ IxfrTransportStrategy -----------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub enum TransportStrategy {
    #[default]
    None,
    Udp,
    Tcp,
}

//------------ XfrSettings ---------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct XfrSettings {
    pub xfr: XfrStrategy,
    pub ixfr_transport: TransportStrategy,
}

//------------ TsigKey -------------------------------------------------------

pub type TsigKey = (tsig::KeyName, tsig::Algorithm);

//------------ Type Aliases --------------------------------------------------

pub type XfrAcl = Acl<(XfrSettings, Option<TsigKey>)>;
pub type NotifyAcl = Acl<Option<TsigKey>>;

//------------ MultiPrimaryXfrStrategy ---------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MultiPrimaryXfrStrategy {
    NotifySourceFirstThenSequentialStoppingAtFirstNewerSerial,
}

//------------ ZoneType ------------------------------------------------------

#[derive(Clone, Debug)]
pub enum ZoneType {
    /// We are primary for the zone and allow the specified (secondary?)
    /// servers to request the zone via XFR. NOTIFY messages will be sent to
    /// zone nameservers on changes to zone content.
    Primary {
        allow_xfr: XfrAcl,
        notify: NotifyAcl,
    },

    /// We are secondary for the zone and will request the zone via XFR from
    /// the specified nameservers, and allow the specified nameservers to
    /// notify us of an update to the zone.
    Secondary {
        multi_primary_xfr_strategy: MultiPrimaryXfrStrategy,
        allow_notify: NotifyAcl,
        request_xfr: XfrAcl,
    },
}

impl ZoneType {
    pub fn new_primary(allow_xfr: XfrAcl, notify: NotifyAcl) -> Self {
        Self::Primary { allow_xfr, notify }
    }

    pub fn new_secondary(
        allow_notify: NotifyAcl,
        request_xfr: XfrAcl,
    ) -> Self {
        Self::Secondary {
            allow_notify,
            request_xfr,
            multi_primary_xfr_strategy: MultiPrimaryXfrStrategy::NotifySourceFirstThenSequentialStoppingAtFirstNewerSerial,
        }
    }
}

impl ZoneType {
    pub fn is_primary(&self) -> bool {
        matches!(self, Self::Primary { .. })
    }

    pub fn is_secondary(&self) -> bool {
        matches!(self, Self::Secondary { .. })
    }
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

//------------ ZoneStatus ----------------------------------------------------

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub enum ZoneRefreshStatus {
    /// Refreshing according to the SOA REFRESH interval.
    #[default]
    Refreshing,

    /// Periodically retrying according to the SOA RETRY interval.
    Retrying,

    /// Refresh triggered by NOTIFY currently in progress.
    NotifyInProgress,
}

//--- Display

impl std::fmt::Display for ZoneRefreshStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneRefreshStatus::Refreshing => f.write_str("refreshing"),
            ZoneRefreshStatus::Retrying => f.write_str("retrying"),
            ZoneRefreshStatus::NotifyInProgress => {
                f.write_str("notify in progress")
            }
        }
    }
}

//------------ ZoneRefreshMetrics --------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ZoneRefreshMetrics {
    zone_created_at: Instant,

    /// None means never checked
    last_refresh_phase_started_at: Option<Instant>,

    /// None means never checked
    last_refresh_attempted_at: Option<Instant>,

    /// None means never checked
    last_soa_serial_check_succeeded_at: Option<Instant>,

    /// None means never checked
    ///
    /// The SOA SERIAL received for the last successful SOA query sent to a
    /// primary for this zone.
    last_soa_serial_check_serial: Option<Serial>,

    /// None means never refreshed
    last_refreshed_at: Option<Instant>,

    /// None means never refreshed
    ///
    /// The SOA SERIAL of the last commit made to this zone.
    last_refresh_succeeded_serial: Option<Serial>,
}

impl Default for ZoneRefreshMetrics {
    fn default() -> Self {
        Self {
            zone_created_at: Instant::now(),
            last_refresh_phase_started_at: Default::default(),
            last_refresh_attempted_at: Default::default(),
            last_soa_serial_check_succeeded_at: Default::default(),
            last_soa_serial_check_serial: Default::default(),
            last_refreshed_at: Default::default(),
            last_refresh_succeeded_serial: Default::default(),
        }
    }
}

//------------ ZoneRefreshState ----------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ZoneRefreshState {
    /// SOA REFRESH
    refresh: Ttl,

    /// SOA RETRY
    retry: Ttl,

    /// SOA EXPIRE
    expire: Ttl,

    /// Refresh status
    status: ZoneRefreshStatus,

    /// Refresh metrics
    metrics: ZoneRefreshMetrics,
}

impl ZoneRefreshState {
    pub fn new(soa: &Soa<Name<Bytes>>) -> Self {
        ZoneRefreshState {
            refresh: soa.refresh(),
            retry: soa.retry(),
            expire: soa.expire(),
            metrics: Default::default(),
            status: Default::default(),
        }
    }
}

impl Default for ZoneRefreshState {
    fn default() -> Self {
        // These values affect how hard and fast we try to provision a
        // secondary zone on startup.
        // TODO: These values should be configurable.
        Self {
            refresh: Ttl::ZERO,
            retry: Ttl::from_mins(5),
            expire: Ttl::from_hours(1),
            status: Default::default(),
            metrics: Default::default(),
        }
    }
}

//------------ ZoneRefreshInstant --------------------------------------------

#[derive(Clone, Debug)]
struct ZoneRefreshInstant {
    cause: ZoneRefreshCause,
    key: ZoneKey,
    end_instant: Instant,
}

impl ZoneRefreshInstant {
    fn new(
        key: (Name<Bytes>, Class),
        refresh: Ttl,
        cause: ZoneRefreshCause,
    ) -> Self {
        trace!(
            "Creating ZoneRefreshInstant for zone {} with refresh duration {} seconds and cause {cause}",
            key.0,
            refresh.into_duration().as_secs()
        );
        let end_instant =
            Instant::now().checked_add(refresh.into_duration()).unwrap();
        Self {
            cause,
            key,
            end_instant,
        }
    }
}

//------------ ZoneRefreshCause ----------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum ZoneRefreshCause {
    ManualTrigger,

    NotifyFromPrimary(IpAddr),

    SoaRefreshTimer,

    SoaRefreshTimerAfterStartup,

    SoaRefreshTimerAfterZoneAdded,

    SoaRetryTimer,
}

impl std::fmt::Display for ZoneRefreshCause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneRefreshCause::ManualTrigger => f.write_str("manual trigger"),
            ZoneRefreshCause::NotifyFromPrimary(primary) => {
                f.write_fmt(format_args!("NOTIFY from {primary}"))
            }
            ZoneRefreshCause::SoaRefreshTimer => {
                f.write_str("SOA REFRESH periodic timer expired")
            }
            ZoneRefreshCause::SoaRefreshTimerAfterStartup => f.write_str(
                "SOA REFRESH timer (scheduled at startup) expired",
            ),
            ZoneRefreshCause::SoaRefreshTimerAfterZoneAdded => f.write_str(
                "SOA REFRESH timer (scheduled at zone addition) expired",
            ),
            ZoneRefreshCause::SoaRetryTimer => {
                f.write_str("SOA RETRY timer expired")
            }
        }
    }
}

//------------ ZoneRefreshTimer ----------------------------------------------

struct ZoneRefreshTimer {
    refresh_instant: ZoneRefreshInstant,
    sleep_fut: Pin<Box<Sleep>>,
}

impl ZoneRefreshTimer {
    fn new(refresh_instant: ZoneRefreshInstant) -> Self {
        let sleep_fut = Box::pin(sleep_until(refresh_instant.end_instant));
        Self {
            refresh_instant,
            sleep_fut,
        }
    }

    fn deadline(&self) -> Instant {
        self.sleep_fut.deadline()
    }

    fn replace(&mut self, new_timer: ZoneRefreshTimer) {
        self.refresh_instant = new_timer.refresh_instant;
        self.sleep_fut
            .as_mut()
            .reset(self.refresh_instant.end_instant);
    }
}

impl Future for ZoneRefreshTimer {
    type Output = ZoneRefreshInstant;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        match self.sleep_fut.poll_unpin(cx) {
            Poll::Ready(()) => Poll::Ready(self.refresh_instant.clone()),
            Poll::Pending => Poll::Pending,
        }
    }
}

//------------ NameServerNameAddr --------------------------------------------

pub type NameServerNameAddr = (StoredName, HashSet<SocketAddr>);

//------------ ZoneNameServers -----------------------------------------------

#[derive(Clone, Debug)]
pub struct ZoneNameServers {
    primary: NameServerNameAddr,
    other: Vec<NameServerNameAddr>,
}

impl ZoneNameServers {
    fn new(primary_name: StoredName, ips: &[IpAddr]) -> Self {
        let unique_ips = Self::to_socket_addrs(ips);
        let primary = (primary_name, unique_ips);
        Self {
            primary,
            other: vec![],
        }
    }

    fn add_ns(&mut self, name: StoredName, ips: &[IpAddr]) {
        let unique_ips = Self::to_socket_addrs(ips);
        self.other.push((name, unique_ips));
    }

    pub fn primary(&self) -> &NameServerNameAddr {
        &self.primary
    }

    pub fn others(&self) -> &[NameServerNameAddr] {
        &self.other
    }

    pub fn addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.primary
            .1
            .iter()
            .chain(self.other.iter().flat_map(|(_name, addrs)| addrs.iter()))
    }

    pub fn notify_set(&self) -> impl Iterator<Item = &SocketAddr> {
        // https://datatracker.ietf.org/doc/html/rfc1996#section-2
        // 2. Definitions and Invariants
        //   "Notify Set      set of servers to be notified of changes to some
        //                    zone.  Default is all servers named in the NS
        //                    RRset, except for any server also named in the
        //                    SOA MNAME. Some implementations will permit the
        //                    name server administrator to override this set
        //                    or add elements to it (such as, for example,
        //                    stealth servers)."
        self.other
            .iter()
            .flat_map(|(_name, addrs)| addrs.difference(&self.primary.1))
    }

    fn to_socket_addrs(ips: &[IpAddr]) -> HashSet<SocketAddr> {
        ips.iter()
            .map(|ip| SocketAddr::new(*ip, IANA_DNS_PORT_NUMBER))
            .collect()
    }
}

//------------ ZoneInfo ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ZoneInfo {
    _catalog_member_id: Option<StoredName>,
    zone_type: ZoneType,
    diffs: Arc<Mutex<ZoneDiffs>>,
    nameservers: Arc<Mutex<Option<ZoneNameServers>>>,
    expired: Arc<AtomicBool>,
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

//------------ ZoneReport ----------------------------------------------------

#[derive(Debug)]
pub struct ZoneReport {
    key: ZoneKey,
    details: ZoneReportDetails,
    timers: Vec<ZoneRefreshInstant>,
    zone_info: ZoneInfo,
}

//--- Display

impl std::fmt::Display for ZoneReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("zone:   {}\n", self.key.0))?;
        f.write_fmt(format_args!("{}", self.details))?;
        if let Ok(nameservers) = self.zone_info.nameservers.try_lock() {
            if let Some(nameservers) = nameservers.as_ref() {
                f.write_str("        nameservers:\n")?;

                let (name, ips) = &nameservers.primary;
                f.write_fmt(format_args!("           {name}: [PRIMARY]"))?;
                if ips.is_empty() {
                    f.write_str(" unresolved")?;
                } else {
                    for ip in ips {
                        f.write_fmt(format_args!(" {ip}"))?;
                    }
                }
                f.write_str("\n")?;

                for (name, ips) in &nameservers.other {
                    f.write_fmt(format_args!("           {name}:"))?;
                    if ips.is_empty() {
                        f.write_str(" unresolved")?;
                    } else {
                        for ip in ips {
                            f.write_fmt(format_args!(" {ip}"))?;
                        }
                    }
                    f.write_str("\n")?;
                }
            }
        }
        if !self.timers.is_empty() {
            f.write_str("        timers:\n")?;
            let now = Instant::now();
            for timer in &self.timers {
                let cause = timer.cause;
                let at = timer
                    .end_instant
                    .checked_duration_since(now)
                    .map(|d| format!("            wait {}s", d.as_secs()))
                    .unwrap_or_else(|| "            wait ?s".to_string());

                f.write_fmt(format_args!("{at} until {cause}\n"))?;
            }
        }
        Ok(())
    }
}

//------------ ZoneReportDetails ---------------------------------------------

#[derive(Debug)]
pub enum ZoneReportDetails {
    Primary,

    PendingSecondary,

    Secondary(ZoneRefreshState),
}

//--- Display

impl std::fmt::Display for ZoneReportDetails {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneReportDetails::Primary => {
                f.write_str("        type: primary\n")?;
                f.write_str("        state: ok\n")
            }
            ZoneReportDetails::PendingSecondary => {
                f.write_str("        type: secondary\n")?;
                f.write_str("        state: pending initial refresh\n")
            }
            ZoneReportDetails::Secondary(state) => {
                let now = Instant::now();
                f.write_str("        type: secondary\n")?;
                let at = match now
                    .checked_duration_since(state.metrics.zone_created_at)
                {
                    Some(duration) => {
                        format!("{}s ago", duration.as_secs())
                    }
                    None => "unknown".to_string(),
                };
                f.write_fmt(format_args!("        created at: {at}\n"))?;
                f.write_fmt(format_args!(
                    "        state: {}\n",
                    state.status
                ))?;

                if state.metrics.last_refreshed_at.is_some() {
                    let last_refreshed_at =
                        state.metrics.last_refreshed_at.unwrap();
                    let serial =
                        state.metrics.last_refresh_succeeded_serial.unwrap();
                    let at =
                        match now.checked_duration_since(last_refreshed_at) {
                            Some(duration) => {
                                format!("{}s ago", duration.as_secs())
                            }
                            None => "unknown".to_string(),
                        };

                    f.write_fmt(format_args!(
                        "        serial: {serial} ({at})\n",
                    ))?;
                }

                let at = match state.metrics.last_refresh_phase_started_at {
                    Some(at) => match now.checked_duration_since(at) {
                        Some(duration) => {
                            format!("{}s ago", duration.as_secs())
                        }
                        None => "unknown".to_string(),
                    },
                    None => "never".to_string(),
                };
                f.write_fmt(format_args!(
                    "        last refresh phase started at: {at}\n"
                ))?;

                let at = match state.metrics.last_refresh_attempted_at {
                    Some(at) => match now.checked_duration_since(at) {
                        Some(duration) => {
                            format!("{}s ago", duration.as_secs())
                        }
                        None => "unknown".to_string(),
                    },
                    None => "never".to_string(),
                };
                f.write_fmt(format_args!(
                    "        last refresh attempted at: {at}\n"
                ))?;

                let at =
                    match state.metrics.last_soa_serial_check_succeeded_at {
                        Some(at) => match now.checked_duration_since(at) {
                            Some(duration) => {
                                format!(
                                    "{}s ago (serial: {})",
                                    duration.as_secs(),
                                    state
                                        .metrics
                                        .last_soa_serial_check_serial
                                        .unwrap()
                                )
                            }
                            None => "unknown".to_string(),
                        },
                        None => "never".to_string(),
                    };
                f.write_fmt(format_args!(
                    "        last successful soa check at: {at}\n"
                ))?;

                let at =
                    match state.metrics.last_soa_serial_check_succeeded_at {
                        Some(at) => match now.checked_duration_since(at) {
                            Some(duration) => {
                                format!(
                                    "{}s ago (serial: {})",
                                    duration.as_secs(),
                                    state
                                        .metrics
                                        .last_soa_serial_check_serial
                                        .unwrap()
                                )
                            }
                            None => "unknown".to_string(),
                        },
                        None => "never".to_string(),
                    };
                f.write_fmt(format_args!(
                    "        last soa check attempted at: {at}\n"
                ))?;

                Ok(())
            }
        }
    }
}

//------------ Event ---------------------------------------------------------

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
enum Event {
    ZoneRefreshRequested {
        cause: ZoneRefreshCause,
        key: ZoneKey,
        at: Option<Ttl>,
    },

    ZoneStatusRequested {
        key: ZoneKey,
        tx: oneshot::Sender<ZoneReport>,
    },

    ZoneChanged(ZoneChangedMsg),

    ZoneAdded(ZoneKey),

    ZoneRemoved(ZoneKey),
}

//------------ Catalog -------------------------------------------------------

/// A set of zones that are kept in sync with other servers.
///
/// Also capable of acting as an RFC 9432 Catalog Zone producer/consumer.
#[derive(Debug)]
pub struct Catalog {
    // cat_zone: Zone, // TODO
    config: Arc<ArcSwap<Config>>,
    key_store: Arc<RwLock<CatalogKeyStore>>,
    pending_zones: Arc<RwLock<HashMap<ZoneKey, Zone>>>,
    member_zones: Arc<ArcSwap<ZoneTree>>,
    loaded_arc: std::sync::RwLock<Arc<ZoneTree>>,
    event_rx: Mutex<Receiver<Event>>,
    event_tx: Sender<Event>,
    running: AtomicBool,
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}

impl Catalog {
    pub fn new() -> Catalog {
        Self::new_with_config(Config::default())
    }

    pub fn new_with_config(config: Config) -> Self {
        let key_store = config.key_store;

        let pending_zones = Default::default();
        let member_zones = ZoneTree::new();
        let member_zones = Arc::new(ArcSwap::from_pointee(member_zones));
        let loaded_arc = std::sync::RwLock::new(member_zones.load_full());
        let (event_tx, event_rx) = mpsc::channel(10);
        let event_rx = Mutex::new(event_rx);
        let config = Arc::new(ArcSwap::from_pointee(Config::default()));

        Catalog {
            // cat_zone,
            config,
            key_store,
            pending_zones,
            member_zones,
            loaded_arc,
            event_rx,
            event_tx,
            running: AtomicBool::new(false),
        }
    }
}

impl Catalog {
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
                .downcast_ref::<CatalogZone>()
                .unwrap();

            match &cat_zone.info().zone_type {
                ZoneType::Primary { notify, .. } => {
                    // https://datatracker.ietf.org/doc/html/rfc1996#autoid-4
                    // 4. Details and Examples
                    //   "4.1. Retaining query state information across host
                    //    reboots is optional, but it is reasonable to simply
                    //    execute an SOA NOTIFY transaction on each authority
                    //    zone when a server first starts."
                    Self::send_notify(zone, notify, self.key_store.clone())
                        .await;
                }

                ZoneType::Secondary { .. } => {
                    match Self::track_zone_freshness(
                        zone,
                        time_tracking.clone(),
                    )
                    .await
                    {
                        Ok(soa_refresh) => {
                            // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.5
                            // 4.3.5. Zone maintenance and transfers
                            //   ..
                            //   "Whenever a new zone is loaded in a
                            //    secondary, the secondary waits REFRESH
                            //    seconds before checking with the primary for
                            //    a new serial."
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
        }

        loop {
            tokio::select! {
                biased;

                msg = event_rx.recv() => {
                    let Some(event) = msg else {
                        // The channel has been closed, i.e. the Catalog
                        // instance has been dropped. Stop performing
                        // background activiities for this catalog.
                        break;
                    };

                    match event {
                        Event::ZoneChanged(msg) => {
                            trace!("Notify message received: {msg:?}");
                            let zones = self.zones();
                            let time_tracking = time_tracking.clone();
                            let event_tx = self.event_tx.clone();
                            let pending_zones = self.pending_zones.clone();
                            let key_store = self.key_store.clone();
                            tokio::spawn(async move {
                                Self::handle_notify(
                                    zones, pending_zones, msg, time_tracking, event_tx, key_store,
                                ).await
                            });
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

                        Event::ZoneRemoved(_key) => {
                            // TODO
                        }

                        Event::ZoneRefreshRequested { key, at, cause } => {
                            Self::refresh_zone_at(cause, key, at, &mut refresh_timers);
                        }

                        Event::ZoneStatusRequested { key, tx } => {
                            let details = if let Some(zone_refresh_info) = time_tracking.read().await.get(&key) {
                                ZoneReportDetails::Secondary(*zone_refresh_info)
                            } else if self.pending_zones.read().await.contains_key(&key) {
                                ZoneReportDetails::PendingSecondary
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
                                .downcast_ref::<CatalogZone>()
                                .unwrap();

                                let zone_info = cat_zone.info().clone();

                                let report = ZoneReport { key, details, timers, zone_info };

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
                            .downcast_ref::<CatalogZone>()
                            .unwrap();

                        if let ZoneType::Secondary{ .. } =
                        &cat_zone.info().zone_type
                        {
                            // If successful this will commit changes to the
                            // zone causing a notify event message to be sent
                            // which will be handled above.
                            match Self::refresh_zone_and_update_state(
                                    timer_info.cause,
                                    zone,
                                    None,
                                    zone_refresh_info,
                                    self.event_tx.clone(),
                                    self.key_store.clone(),
                                )
                                .await
                            {
                                Ok(()) => {
                                    if is_pending_zone {
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
            let is_primary = zone.zone_type().is_primary();
            let zone = Self::wrap_zone(zone, self.event_tx.clone());
            let key = zone.key();

            if is_primary {
                Self::update_known_nameservers_for_zone(&zone).await;
                new_zones.insert_zone(zone)?;
            } else {
                // Don't add secondary zones immediately as they may be empty
                // until refreshed. Instead add them in run() once it has been
                // determined if they are empty or that the initial refresh
                // has been performed successfully. This prevents callers of
                // get_zone() or find_zone() attempting to use an empty zone.
                self.pending_zones.write().await.insert(zone.key(), zone);
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

    pub async fn notify_zone_changed(
        &self,
        class: Class,
        apex_name: &StoredName,
        source: IpAddr,
    ) -> Result<(), CatalogError> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(CatalogError::NotRunning);
        }

        if self.zones().get_zone(apex_name, class).is_none() {
            let key = (apex_name.clone(), class);
            if !self.pending_zones.read().await.contains_key(&key) {
                return Err(CatalogError::UnknownZone);
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
        // quick so we leave that to the running Catalog task to handle.

        let msg = ZoneChangedMsg {
            class,
            apex_name: apex_name.clone(),
            source: Some(source),
        };

        send_zone_changed_msg(&self.event_tx, msg)
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

    /// Get a status report for a zone.
    ///
    /// The Catalog must be [`run()`]ing for this to work.
    ///
    /// When unable to report the status for a zone the error will be one of
    /// the following:
    ///   - [`CatalogError::NotRunning`]
    ///   - [`CatalogError::UnknownZone`]
    pub async fn zone_status(
        &self,
        apex_name: &StoredName,
        class: Class,
    ) -> Result<ZoneReport, CatalogError> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        // If we are unable to send it means that the Catalog is not running
        // so cannot respond to the request.
        self.event_tx
            .send(Event::ZoneStatusRequested {
                key: (apex_name.clone(), class),
                tx,
            })
            .await
            .map_err(|_| CatalogError::NotRunning)?;

        // If the zone is not known we get a RecvError as the Catalog will not
        // send a status report back over the oneshot channel but will just
        // drop the sending end causing the client end to see that the channel
        // has been closed.
        rx.await.map_err(|_| CatalogError::UnknownZone)
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

impl Catalog {
    /// Wrap a [`Zone`] so that we get notified when it is modified.
    fn wrap_zone(zone: TypedZone, notify_tx: Sender<Event>) -> Zone {
        let diffs = Arc::new(Mutex::new(ZoneDiffs::new()));
        let nameservers = Arc::new(Mutex::new(None));
        let expired = Arc::new(AtomicBool::new(false));

        let (zone_store, zone_type) = zone.into_inner();

        let zone_info = ZoneInfo {
            _catalog_member_id: None, // TODO
            zone_type,
            diffs,
            nameservers,
            expired,
        };

        let new_store = CatalogZone::new(notify_tx, zone_store, zone_info);
        Zone::new(new_store)
    }

    async fn send_notify(
        zone: &Zone,
        notify: &NotifyAcl,
        key_store: Arc<RwLock<CatalogKeyStore>>,
    ) {
        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<CatalogZone>()
            .unwrap();

        let zone_info = cat_zone.info();

        // TODO: Make sending to the notify set configurable
        let locked_nameservers = zone_info.nameservers.lock().await;
        if let Some(nameservers) = locked_nameservers.as_ref() {
            Self::send_notify_to_addrs(
                cat_zone.apex_name().clone(),
                nameservers.notify_set(),
                key_store.clone(),
                zone_info,
            )
            .await;
        }

        if !notify.is_empty() {
            Self::send_notify_to_addrs(
                cat_zone.apex_name().clone(),
                notify.addrs(),
                key_store,
                zone_info,
            )
            .await;
        }
    }

    async fn send_notify_to_addrs(
        apex_name: StoredName,
        notify_set: impl Iterator<Item = &SocketAddr>,
        key_store: Arc<RwLock<CatalogKeyStore>>,
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

        // TSIG TODO: let key = key_store .read() .await
        // .get_key(&Name::root_bytes(), Algorithm::Sha256) .unwrap(); let mut
        // msg = msg.additional(); let txn = ClientTransaction::request(key,
        //     &mut msg, Time48::now()).unwrap();
        //
        // TODO: TSIG cannot be done here, it must be done by RequestMessage,
        // because RequestMessage can alter the message such as replacing any
        // OPT records in the additional section, and TSIG needs to add its
        // own RR to the additional section AFTER all other changes have been
        // made to the message. It would also have to verify the response as
        // it would own the TSIG ClientTransaction or ClientSequence object
        // that is required in order to do response verification.
        let readable_key_store = key_store.read().await;

        for nameserver_addr in notify_set {
            let dgram_config = dgram_config.clone();
            let req = RequestMessage::new(msg.clone());
            let nameserver_addr = *nameserver_addr;

            let tsig_key = if let ZoneType::Primary { notify, .. } =
                &zone_info.zone_type
            {
                if let Some(Some(key_info)) = notify.get(&nameserver_addr) {
                    let key = readable_key_store.get(key_info).cloned();

                    if key.is_some() {
                        debug!("Found TSIG key '{}' (algorith {}) for NOTIFY to {nameserver_addr}", key_info.0, key_info.1);
                    }

                    key
                } else {
                    None
                }
            } else {
                None
            };

            tokio::spawn(async move {
                let udp_connect = UdpConnect::new(nameserver_addr);
                let client = Connection::with_config(
                    udp_connect,
                    dgram_config.clone(),
                );

                let client = auth::Connection::new(tsig_key.clone(), client);

                trace!("Sending NOTIFY to nameserver {nameserver_addr}");
                if let Err(err) =
                    client.send_request(req.clone()).get_response().await
                {
                    // TODO: Add retry support.
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
            .downcast_ref::<CatalogZone>()
            .unwrap();

        if !matches!(cat_zone.info().zone_type, ZoneType::Secondary { .. }) {
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
                Ok(Some(e.get().refresh))
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
        key_store: Arc<RwLock<CatalogKeyStore>>,
    ) {
        // Do we have the zone that is being updated?
        let pending_zones = pending_zones.read().await;
        let zone =
            if let Some(zone) = zones.get_zone(&msg.apex_name, msg.class) {
                zone
            } else if let Some(zone) =
                pending_zones.get(&(msg.apex_name.clone(), msg.class))
            {
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
            .downcast_ref::<CatalogZone>()
            .unwrap();

        // Are we the primary for the zone? We don't accept external
        // notifications for updates to a zone that we are authoritative for.
        let zone_info = cat_zone.info();

        let (source, allow_notify) = match (msg.source, &zone_info.zone_type)
        {
            (None, ZoneType::Primary { notify, .. }) => {
                // A local notification that a zone that we are primary for
                // has been changed locally.
                trace!(
                    "Local change occurred in primary zone '{}'",
                    msg.apex_name
                );

                Self::update_known_nameservers_for_zone(zone).await;
                Self::send_notify(zone, notify, key_store).await;
                return;
            }

            (None, ZoneType::Secondary { .. }) => {
                // A local notification that a zone we are secondary for has
                // been changed locally. This happens when we applied changes
                // received via XFR from a remote primary to a local secondary
                // zone. The REFRESH timer will have already been reset by
                // [`refresh_zone_and_update_state()`] which fetched and
                // applied the remote changes.
                trace!(
                    "Local change occurred in secondary zone '{}'",
                    msg.apex_name
                );

                Self::update_known_nameservers_for_zone(zone).await;
                return;
            }

            (Some(source), ZoneType::Secondary { allow_notify, .. }) => {
                // A remote notification that a zone that we are secondary for
                // has been updated on the remote server. If the notification
                // is legitimate we will want to check if the remote copy of
                // the zone is indeed newer than our copy and then fetch the
                // changes.
                trace!("Remote change notification received for secondary zone '{}'", msg.apex_name);
                (source, allow_notify)
            }

            (Some(_), ZoneType::Primary { .. }) => {
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

        if !Self::is_known_primary(allow_notify, &source, zone).await {
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
            zone_refresh_info.status,
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

        zone_refresh_info.status = ZoneRefreshStatus::NotifyInProgress;

        let initial_xfr_addr = SocketAddr::new(source, IANA_DNS_PORT_NUMBER);
        if let Err(()) = Self::refresh_zone_and_update_state(
            ZoneRefreshCause::NotifyFromPrimary(source),
            zone,
            Some(initial_xfr_addr),
            zone_refresh_info,
            event_tx,
            key_store,
        )
        .await
        {
            // TODO
        }
    }

    #[allow(clippy::mutable_key_type)]
    async fn refresh_zone_and_update_state(
        cause: ZoneRefreshCause,
        zone: &Zone,
        initial_xfr_addr: Option<SocketAddr>,
        zone_refresh_info: &mut ZoneRefreshState,
        event_tx: Sender<Event>,
        key_store: Arc<RwLock<CatalogKeyStore>>,
    ) -> Result<(), ()> {
        match cause {
            ZoneRefreshCause::ManualTrigger
            | ZoneRefreshCause::NotifyFromPrimary(_)
            | ZoneRefreshCause::SoaRefreshTimer
            | ZoneRefreshCause::SoaRefreshTimerAfterStartup
            | ZoneRefreshCause::SoaRefreshTimerAfterZoneAdded => {
                zone_refresh_info.metrics.last_refresh_phase_started_at =
                    Some(Instant::now());
                zone_refresh_info.metrics.last_refresh_attempted_at =
                    Some(Instant::now());
            }
            ZoneRefreshCause::SoaRetryTimer => {
                zone_refresh_info.metrics.last_refresh_attempted_at =
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
            key_store,
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

                if zone_refresh_info.status == ZoneRefreshStatus::Retrying {
                    let time_of_last_soa_check = zone_refresh_info
                        .metrics
                        .last_soa_serial_check_succeeded_at
                        .unwrap_or(zone_refresh_info.metrics.zone_created_at);

                    if let Some(duration) = Instant::now()
                        .checked_duration_since(time_of_last_soa_check)
                    {
                        if duration > zone_refresh_info.expire.into_duration()
                        {
                            let cat_zone = zone
                                .as_ref()
                                .as_any()
                                .downcast_ref::<CatalogZone>()
                                .unwrap();

                            cat_zone.mark_expired();

                            // TODO: Should we keep trying to refresh an
                            // expired zone so that we can bring it back to
                            // life if we are able to connect to the primary?

                            return Err(());
                        }
                    }
                }

                zone_refresh_info.status = ZoneRefreshStatus::Retrying;

                // Schedule a zone refresh according to the SOA RETRY timer value.
                Self::schedule_zone_refresh(
                    ZoneRefreshCause::SoaRetryTimer,
                    &event_tx,
                    key,
                    zone_refresh_info.retry,
                )
                .await;

                Err(())
            }

            Ok(new_soa) => {
                if let Some(new_soa) = new_soa {
                    // Refresh succeeded:
                    zone_refresh_info.refresh = new_soa.refresh();
                    zone_refresh_info.retry = new_soa.retry();
                    zone_refresh_info.expire = new_soa.expire();
                    zone_refresh_info.metrics.last_refreshed_at =
                        Some(Instant::now());
                } else {
                    // No transfer was required, either because transfer is not
                    // enabled for the zone or the zone is up-to-date.
                }

                zone_refresh_info.status = ZoneRefreshStatus::Refreshing;

                // Schedule a zone refresh according to the SOA REFRESH timer value.
                Self::schedule_zone_refresh(
                    ZoneRefreshCause::SoaRefreshTimer,
                    &event_tx,
                    key,
                    zone_refresh_info.refresh,
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
        key_store: Arc<RwLock<CatalogKeyStore>>,
    ) -> Result<Option<Soa<Name<Bytes>>>, CatalogError> {
        // Was this zone already refreshed recently?
        if let Some(last_refreshed) =
            zone_refresh_info.metrics.last_refreshed_at
        {
            if let Some(elapsed) =
                Instant::now().checked_duration_since(last_refreshed)
            {
                if elapsed < MIN_DURATION_BETWEEN_ZONE_REFRESHES {
                    // Don't refresh, we refreshed very recently
                    debug!("Skipping refresh of zone '{}' as it was refreshed less than {}s ago ({}s)",
                        zone.apex_name(), MIN_DURATION_BETWEEN_ZONE_REFRESHES.as_secs(), elapsed.as_secs());
                    return Ok(None);
                }
            }
        }

        // Determine which strategy to use if the zone has multiple primaries
        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<CatalogZone>()
            .unwrap();

        let ZoneType::Secondary {
            multi_primary_xfr_strategy,
            request_xfr,
            ..
        } = &cat_zone.info().zone_type
        else {
            unreachable!();
        };

        // TODO: If we later have more than one MultiPrimaryXfrStrategy,
        // adjust our behaviour to match the requested strategy.
        // TODO: Factor out the multi-primary strategy to a generic type on
        // Catalog that implements a trait to make it pluggable.
        assert!(matches!(multi_primary_xfr_strategy, MultiPrimaryXfrStrategy::NotifySourceFirstThenSequentialStoppingAtFirstNewerSerial));

        // Determine our current SOA SERIAL value so that we can check that
        // the primary is higher. If the zone is a new secondary it will not
        // have a SOA RR and any available data for the zone available at a
        // primary should be accepted.
        let soa = Self::read_soa(&zone.read(), zone.apex_name().clone())
            .await
            .map_err(|_out_of_zone_err| CatalogError::InternalError)?;

        let current_serial = soa.map(|(soa, _)| soa.serial());

        // Determine the primary server addresses to visit and in which order.
        let primary_addrs =
            initial_xfr_addr.iter().chain(request_xfr.addrs());

        let mut num_ok_primaries = 0;
        let mut saved_err = None;

        for primary_addr in primary_addrs {
            if let Some((xfr_settings, tsig_key)) =
                request_xfr.get(primary_addr)
            {
                let res = Self::refresh_zone_from_addr(
                    zone,
                    current_serial,
                    *primary_addr,
                    xfr_settings,
                    tsig_key,
                    zone_refresh_info,
                    key_store.clone(),
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
                        // Transfer failed. This shuold already have been
                        // logged along with more details about the transfer
                        // than we have here. Try the next primary.
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
        xfr_settings: &XfrSettings,
        tsig_key: &Option<TsigKey>,
        zone_refresh_info: &mut ZoneRefreshState,
        key_store: Arc<RwLock<CatalogKeyStore>>,
    ) -> Result<Option<Soa<Name<Bytes>>>, CatalogError> {
        // TODO: Replace this loop with one, or two, calls to a helper fn.
        // Try at least once, at most twice (when using IXFR -> AXFR fallback)
        for i in 0..=1 {
            // Determine the kind of transfer to use if the zone is outdated
            let rtype = match xfr_settings.xfr {
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

            // Build the SOA request message
            let msg = MessageBuilder::new_vec();
            let mut msg = msg.question();
            msg.push((zone.apex_name(), Rtype::SOA)).unwrap();
            let msg = msg.into_message();
            let req = RequestMessage::new(msg);

            // Fetch the SOA serial using the appropriate transport
            let transport = match rtype {
                Rtype::AXFR => TransportStrategy::Tcp,
                Rtype::IXFR => xfr_settings.ixfr_transport,
                _ => unreachable!(),
            };

            // https://datatracker.ietf.org/doc/html/rfc5936#section-6
            // 6.  Zone Integrity
            // ...
            //   "Besides best attempts at securing TCP connections, DNS
            //    implementations SHOULD provide means to make use of "Secret
            //    Key Transaction Authentication for DNS (TSIG)" [RFC2845]
            //    and/or "DNS Request and Transaction Signatures ( SIG(0)s )"
            //    [RFC2931] to allow AXFR clients to verify the contents.
            //    These techniques MAY also be used for authorization."
            //
            // When constructing an appropriate DNS client below to query the
            // SOA and to do XFR a TSIG signing/validating "auth" connection
            // is constructed if a key is specified and available.

            let locked = key_store.read().await;
            let key = tsig_key.as_ref().and_then(|v| locked.get(v));

            // Query the SOA serial of the primary via the chosen transport.
            let client = match transport {
                TransportStrategy::None => return Ok(None),

                TransportStrategy::Udp => {
                    let udp_connect = UdpConnect::new(primary_addr);
                    let mut dgram_config = dgram::Config::new();
                    dgram_config.set_max_parallel(1);
                    dgram_config
                        .set_read_timeout(Duration::from_millis(1000));
                    dgram_config.set_max_retries(1);
                    dgram_config.set_udp_payload_size(Some(1400));
                    let client = dgram::Connection::with_config(
                        udp_connect,
                        dgram_config,
                    );

                    Conn::Udp(auth::Connection::new(key.cloned(), client))
                }

                TransportStrategy::Tcp => {
                    let res = TcpStream::connect(primary_addr).await;

                    // TODO: Replace with inspect_err() if our MSRV increases to 1.76?
                    if let Err(err) = &res {
                        error!(
                            "Unable to refresh zone '{}' by {rtype} from {primary_addr}: {err}",
                            zone.apex_name(),
                        );
                    }

                    let tcp_stream = res?;

                    let mut stream_config = stream::Config::new();
                    stream_config
                        .set_response_timeout(Duration::from_secs(2));
                    // Allow time between the SOA query response and sending
                    // the AXFR/IXFR request.
                    stream_config
                        .set_initial_idle_timeout(Duration::from_secs(5));
                    // Allow much more time
                    stream_config.set_streaming_response_timeout(
                        Duration::from_secs(30),
                    );
                    let (client, transport) = stream::Connection::with_config(
                        tcp_stream,
                        stream_config,
                    );

                    tokio::spawn(async move {
                        transport.run().await;
                        trace!("XFR TCP connection terminated");
                    });

                    Conn::Tcp(auth::Connection::new(key.cloned(), client))
                }
            };

            trace!(
                "Sending SOA query for zone '{}' to {primary_addr}",
                zone.apex_name()
            );
            let send_request = &mut client.send_request(req);
            let msg = send_request.get_response().await?;

            let newer_data_available = Self::check_primary_soa_serial(
                msg,
                zone_refresh_info,
                current_serial,
            )
            .await?;

            if !newer_data_available {
                return Ok(None);
            }

            trace!(
                "Refreshing zone '{}' by {rtype} from {primary_addr}",
                zone.apex_name()
            );
            let res = Self::do_xfr(
                client,
                zone,
                primary_addr,
                rtype,
                zone_refresh_info,
            )
            .await;

            if rtype == Rtype::IXFR
                && matches!(
                    res,
                    Err(CatalogError::ResponseError(OptRcode::NOTIMP))
                )
            {
                trace!("Primary {primary_addr} doesn't support IXFR");
                continue;
            }

            return res;
        }

        Ok(None)
    }

    /// Does the primary have a newer serial than us?
    ///
    /// Returns Ok(true) if so, Ok(false) if its serial is equal or older, or
    /// Err if the response message indicated an error.
    async fn check_primary_soa_serial(
        msg: Message<Bytes>,
        zone_refresh_info: &mut ZoneRefreshState,
        current_serial: Option<Serial>,
    ) -> Result<bool, CatalogError> {
        if msg.no_error() {
            if let Ok(answer) = msg.answer() {
                let mut records = answer.limit_to::<Soa<_>>();
                let record = records.next();
                if let Some(Ok(record)) = record {
                    let serial_at_primary = record.data().serial();

                    zone_refresh_info
                        .metrics
                        .last_soa_serial_check_succeeded_at =
                        Some(Instant::now());

                    zone_refresh_info.metrics.last_soa_serial_check_serial =
                        Some(serial_at_primary);

                    // The serial at the primary can't be stale
                    // compared to ours if we don't have a serial yet.
                    let newer_data_available = current_serial
                        .map(|current| current < serial_at_primary)
                        .unwrap_or(true);

                    debug!("Current: {current_serial:?}");
                    debug!("Primary: {serial_at_primary:?}");
                    debug!("Newer data available: {newer_data_available}");

                    return Ok(newer_data_available);
                }
            }
        }

        Err(CatalogError::ResponseError(msg.opt_rcode()))
    }

    async fn do_xfr(
        client: Conn<RequestMessage<Vec<u8>>>,
        zone: &Zone,
        primary_addr: SocketAddr,
        mut xfr_type: Rtype,
        zone_refresh_info: &mut ZoneRefreshState,
    ) -> Result<Option<Soa<Name<Bytes>>>, CatalogError> {
        // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.5
        // 4.3.5. Zone maintenance and transfers
        //   ..
        //   "If the serial field in the secondary's zone copy is
        //    equal to the serial returned by the primary, then no
        //    changes have occurred, and the REFRESH interval wait is
        //    restarted."
        //
        // Create a Tokio sleep future that will awaken when the REFRESH
        // interval expires, yielding the key of the zone which is ready
        // to be refreshed.

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
                return Err(CatalogError::InternalError);
            };
            msg.push((zone.apex_name(), ttl, soa)).unwrap();
            msg
        } else {
            msg.authority()
        };

        let msg = msg.into_message();
        let req = RequestMessage::new(msg);

        let mut expected_initial_soa_seen_count = match xfr_type {
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
        let mut initial_soa = None;

        let writable = write.open(true).await?;
        let mut send_request = client.send_request(req);
        let mut i = 0;
        let mut n = 0;
        let mut initial_soa_serial = None;
        let mut initial_soa_serial_seen_count = 0;
        let start_time = Instant::now();
        let mut last_progress_report = start_time;

        // https://datatracker.ietf.org/doc/html/rfc5936#section-6
        // 6.  Zone Integrity "An AXFR client MUST ensure that only a
        //   successfully transferred copy of the zone data can be used to
        //    serve this zone.  Previous description and implementation
        //    practice has introduced a two-stage model of the whole zone
        //    synchronization procedure: Upon a trigger event (e.g., when
        //    polling of a SOA resource record detects a change in the SOA
        //    serial number, or when a DNS NOTIFY request [RFC1996] is
        //    received), the AXFR session is initiated, whereby the zone data
        //    are saved in a zone file or database (this latter step is
        //    necessary anyway to ensure proper restart of the server); upon
        //    successful completion of the AXFR operation and some sanity
        //    checks, this data set is "loaded" and made available for serving
        //    the zone in an atomic operation, and flagged "valid" for use
        //    during the next restart of the DNS server; if any error is
        //    detected, this data set MUST be deleted, and the AXFR client
        //    MUST continue to serve the previous version of the zone, if it
        //    did before.  The externally visible behavior of an AXFR client
        //    implementation MUST be equivalent to that of this two- stage
        //    model."
        //
        // Regarding "whereby the zone data are saved in a zone file or
        // database (this latter step is necessary anyway to ensure proper
        // restart of the server)" and "- this is NOT done here. We only
        // commit changes to memory. It is left for a client to wrap the zone
        // and detect the call to commit() and at that point save the zone if
        // wanted. See `ArchiveZone` in examples/serve-zone.rs for an example.

        'outer: loop {
            let msg = send_request.get_response().await?;
            trace!("Received response {i}");
            i += 1;

            // TSIG: This seems wasteful that we have to make a copy
            // of the message bytes before we can do TSIG validation
            // but as the underlying message octets may be stored as a
            // type like Bytes that can be cloned by reference
            // counting or other such means of sharing a single set of
            // bytes we cannot modify those bytes as required for TSIG
            // validation because that would modify the views of the
            // same message bytes visible to other parts of the
            // program.
            // if let Some(seq) = &mut seq {
            //     let mut bytes =
            //         Vec::with_capacity(msg.as_slice().len());
            //     bytes.extend_from_slice(msg.as_slice());
            //     let mut tsig_msg =
            //         Message::from_octets(bytes).unwrap();

            //     if let Err(err) =
            //         seq.answer(&mut tsig_msg, Time48::now())
            //     {
            //         error!("TSIG validation failed: {err}");
            //         return Err(());
            //     }
            // }

            if msg.no_error() {
                match msg.answer() {
                    Ok(answer) => {
                        let records =
                            answer.limit_to::<ZoneRecordData<_, _>>();
                        for record in records.flatten() {
                            trace!("XFR record {n}: {record:?}");

                            if xfr_type == Rtype::IXFR
                                && n == 1
                                && initial_soa_serial_seen_count == 1
                                && record.rtype() != Rtype::SOA
                            {
                                // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                                // 4. Response Format
                                //   "If incremental zone transfer is not available, the entire zone is
                                //    returned.  The first and the last RR of the response is the SOA
                                //    record of the zone.  I.e. the behavior is the same as an AXFR
                                //    response except the query type is IXFR."
                                debug!("IXFR response appears to be AXFR, switching...");
                                xfr_type = Rtype::AXFR;
                                expected_initial_soa_seen_count = 2;
                            }

                            let owner = record.owner().to_owned();
                            let ttl = record.ttl();
                            let rtype = record.rtype();
                            let data = record.into_data().flatten_into();

                            if let ZoneRecordData::Soa(soa) = &data {
                                if let Some(initial_soa_serial) =
                                    initial_soa_serial
                                {
                                    if initial_soa_serial == soa.serial() {
                                        // AXFR end SOA detected.
                                        // Notify transport that no
                                        // more responses are
                                        // expected.
                                        initial_soa_serial_seen_count += 1;
                                        if initial_soa_serial_seen_count
                                            == expected_initial_soa_seen_count
                                        {
                                            trace!("Closing response stream at record nr {i} (soa seen count = {initial_soa_serial_seen_count})");
                                            send_request.stream_complete()?;
                                            break 'outer;
                                        }
                                    }
                                } else {
                                    initial_soa_serial = Some(soa.serial());
                                    initial_soa = Some(soa.clone());
                                    initial_soa_serial_seen_count = 1;
                                }
                            }

                            n += 1;

                            let now = Instant::now();
                            if now
                                .duration_since(last_progress_report)
                                .as_secs()
                                > 10
                            {
                                let seconds_so_far =
                                    now.duration_since(start_time).as_secs()
                                        as f64;
                                let records_per_second =
                                    ((n as f64) / seconds_so_far).floor()
                                        as i64;
                                info!("XFR progress report for zone '{}': Received {n} records in {i} responses in {} seconds ({} records/second)", zone.apex_name(), seconds_so_far, records_per_second);
                                last_progress_report = now;
                            }

                            let mut end_node: Option<
                                Box<dyn WritableZoneNode>,
                            > = None;

                            let name = mk_relative_name_iterator(
                                zone.apex_name(),
                                &owner,
                            )
                            .map_err(|_| CatalogError::InternalError)?;

                            for label in name {
                                trace!("Relativised label: {label}");
                                end_node = Some(
                                    match end_node {
                                        Some(new_node) => {
                                            new_node.update_child(label)
                                        }
                                        None => writable.update_child(label),
                                    }
                                    .await
                                    .map_err(|_| {
                                        CatalogError::InternalError
                                    })?,
                                );
                            }

                            let mut rrset = Rrset::new(rtype, ttl);
                            rrset.push_data(data);

                            trace!("Adding RRset: {rrset:?}");
                            let rrset = SharedRrset::new(rrset);
                            match end_node {
                                Some(n) => {
                                    trace!("Adding RRset at end_node");
                                    n.update_rrset(rrset).await.map_err(
                                        |_| CatalogError::InternalError,
                                    )?;
                                }
                                None => {
                                    trace!("Adding RRset at root");
                                    writable
                                        .update_rrset(rrset)
                                        .await
                                        .map_err(|_| {
                                            CatalogError::InternalError
                                        })?;
                                }
                            }
                        }
                    }

                    Err(err) => {
                        error!("Error while parsing XFR ANSWER: {err}");
                        return Err(CatalogError::RequestError(
                            request::Error::MessageParseError,
                        ));
                    }
                }
            } else {
                return Err(CatalogError::ResponseError(msg.opt_rcode()));
            }
        }

        info!("XFR progress report for zone '{}': Transfer complete, commiting changes.", zone.apex_name());

        // Ensure that there are no dangling references to the created diff
        // (otherwise commit() will panic).
        drop(writable);

        // TODO
        write.commit(false).await?;

        let new_serial = initial_soa.as_ref().unwrap().serial();
        zone_refresh_info.metrics.last_refresh_succeeded_serial =
            Some(new_serial);

        info!(
            "Zone '{}' has been updated to serial {} by {xfr_type} from {}",
            zone.apex_name(),
            new_serial,
            primary_addr,
        );

        Ok(initial_soa)
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
        acl: &'a NotifyAcl,
        source: &IpAddr,
        zone: &Zone,
    ) -> bool {
        let source_addr = SocketAddr::new(*source, IANA_DNS_PORT_NUMBER);
        if acl.contains(&source_addr) {
            trace!("Source IP {source} is on the ACL for the zone.");
            return true;
        } else {
            trace!("Source IP {source} is NOT on the ACL for the zone.");
        }

        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<CatalogZone>()
            .unwrap();

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
            .downcast_ref::<CatalogZone>()
            .unwrap();

        if let Ok(nameservers) = Self::identify_nameservers(zone).await {
            *cat_zone.info().nameservers.lock().await = Some(nameservers);
        };
    }
}

impl Catalog {
    /// The entire tree of zones managed by this [`Catalog`] instance.
    pub fn zones(&self) -> Arc<ZoneTree> {
        self.loaded_arc.read().unwrap().clone()
    }

    /// The set of "active" zones managed by this [`Catalog`] instance.
    ///
    /// Excludes:
    ///   - Newly added empty secondary zones still pending initial refresh.
    ///   - Expired zones.
    pub fn get_zone(
        &self,
        apex_name: &impl ToName,
        class: Class,
    ) -> Option<Zone> {
        let zones = self.zones();

        if let Some(zone) = zones.get_zone(apex_name, class) {
            let cat_zone = zone
                .as_ref()
                .as_any()
                .downcast_ref::<CatalogZone>()
                .unwrap();

            if cat_zone.is_active() {
                return Some(zone.clone());
            }
        }

        None
    }

    /// Gets the closest matching "active" [`Zone`] for the given QNAME and
    /// CLASS, if any.
    ///
    /// Excludes:
    ///   - Newly added empty secondary zones still pending initial refresh.
    ///   - Expired zones.
    pub fn find_zone(
        &self,
        qname: &impl ToName,
        class: Class,
    ) -> Option<Zone> {
        let zones = self.zones();

        if let Some(zone) = zones.find_zone(qname, class) {
            let cat_zone = zone
                .as_ref()
                .as_any()
                .downcast_ref::<CatalogZone>()
                .unwrap();

            if cat_zone.is_active() {
                return Some(zone.clone());
            }
        }

        None
    }
}

impl Catalog {
    fn update_lodaded_arc(&self) {
        *self.loaded_arc.write().unwrap() = self.member_zones.load_full();
    }
}

async fn send_zone_changed_msg(
    tx: &Sender<Event>,
    msg: ZoneChangedMsg,
) -> Result<(), SendError<Event>> {
    tx.send(Event::ZoneChanged(msg)).await
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

//------------ TypedZone -----------------------------------------------------

#[derive(Debug)]
pub struct TypedZone {
    store: Arc<dyn ZoneStore>,
    zone_type: ZoneType,
}

impl TypedZone {
    pub fn new(zone: Zone, zone_type: ZoneType) -> TypedZone {
        TypedZone {
            store: zone.into_inner(),
            zone_type,
        }
    }
    pub fn into_inner(self) -> (Arc<dyn ZoneStore>, ZoneType) {
        (self.store, self.zone_type)
    }

    pub fn zone_type(&self) -> &ZoneType {
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
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>> + Send>> {
        self.store.clone().write()
    }

    fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }
}

//------------ CatalogZone ---------------------------------------------------

#[derive(Debug)]
pub struct CatalogZone {
    notify_tx: Sender<Event>,
    store: Arc<dyn ZoneStore>,
    info: ZoneInfo,
}

impl CatalogZone {
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
        !self.info.expired.load(Ordering::Relaxed)
    }

    fn mark_expired(&self) {
        self.info.expired.store(true, Ordering::SeqCst);
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
    notify_tx: Sender<Event>,
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

#[derive(Debug)]
pub enum CatalogError {
    NotRunning,
    InternalError,
    UnknownZone,
    RequestError(request::Error),
    ResponseError(OptRcode),
    IoError(io::Error),
}

//--- Display

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CatalogError::NotRunning => f.write_str("Catalog not running"),
            CatalogError::InternalError => {
                f.write_str("Internal Catalog error")
            }
            CatalogError::UnknownZone => f.write_str("Unknown zone"),
            CatalogError::RequestError(err) => f.write_fmt(format_args!(
                "Request sent by Catalog failed: {err}"
            )),
            CatalogError::ResponseError(err) => f.write_fmt(format_args!(
                "Error response received by Catalog: {err}"
            )),
            CatalogError::IoError(err) => f.write_fmt(format_args!(
                "I/O error during Catalog operation: {err}"
            )),
        }
    }
}

//--- From request::Error

impl From<request::Error> for CatalogError {
    fn from(err: request::Error) -> Self {
        Self::RequestError(err)
    }
}

//--- From io::Error

impl From<io::Error> for CatalogError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

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

//-----------------

// if msg.header().rcode() == Rcode::NOTIMP
// && matches!(
//     xfr_settings.xfr,
//     XfrStrategy::IxfrWithAxfrFallback
// )
// {
// // Try to fallback.
// continue;
// }

pub enum Conn<S: Send + Sync> {
    Udp(auth::Connection<dgram::Connection<UdpConnect>>),
    Tcp(auth::Connection<stream::Connection<AuthenticatedRequestMessage<S>>>),
}

impl<CR: ComposeRequest + Send + Sync + 'static> SendRequest<CR>
    for Conn<CR>
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn request::GetResponse + Send + Sync> {
        match self {
            Conn::Udp(conn) => conn.send_request(request_msg),
            Conn::Tcp(conn) => conn.send_request(request_msg),
        }
    }
}
