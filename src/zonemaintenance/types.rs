use core::fmt::Debug;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use std::boxed::Box;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;
use std::future::Future;
use std::net::SocketAddr;
use std::string::ToString;
use std::sync::Arc;
use std::vec::Vec;

use bytes::Bytes;
use futures_util::FutureExt;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{sleep_until, Instant, Sleep};
use tracing::trace;

use crate::base::iana::Class;
use crate::base::net::IpAddr;
use crate::base::{CanonicalOrd, Name, Serial, ToName, Ttl};
use crate::rdata::Soa;
use crate::tsig::{self, Algorithm, Key, KeyName, KeyStore};
use crate::zonetree::{StoredName, ZoneDiff, ZoneKey};

//------------ Constants -----------------------------------------------------

pub(super) const IANA_DNS_PORT_NUMBER: u16 = 53;

// TODO: This should be configurable.
pub(super) const MIN_DURATION_BETWEEN_ZONE_REFRESHES: tokio::time::Duration =
    tokio::time::Duration::new(0, 0);

//------------ Type Aliases --------------------------------------------------

/// A store of TSIG keys index by key name and algorithm.
pub type ZoneMaintainerKeyStore = HashMap<(KeyName, Algorithm), Key>;

impl KeyStore for Arc<HashMap<(KeyName, Algorithm), Key>> {
    type Key = Key;

    fn get_key<N: ToName>(
        &self,
        name: &N,
        algorithm: Algorithm,
    ) -> Option<Self::Key> {
        if let Ok(name) = name.try_to_name() {
            self.get(&(name, algorithm)).cloned()
        } else {
            None
        }
    }
}

//------------ SrcDstConfig --------------------------------------------------

/// A mapping of network source/destination to some config `T`.
///
/// Maps source addresses (a `SocketAddress` with port 0, i.e. just an
/// `IpAddr`, as we can't know in advance the port number a caller will use),
/// or destination addresses (a `SocketAddr` including port), to some user
/// provided data.
///
/// TODO: Change this to support net blocks as the source once PR 340 (which
/// extends COOKIE middleware to use net blocks) is resolved.
#[derive(Clone, Debug, Default)]
pub struct SrcDstConfig<T: Clone + Debug + Default> {
    entries: HashMap<SocketAddr, T>,
}

impl<T: Clone + Debug + Default> SrcDstConfig<T> {
    /// Creates a new empty access control list.
    pub fn new() -> Self {
        Default::default()
    }

    /// Adds a rule allowing inbound access from the given IP address.
    pub fn add_src(&mut self, addr: IpAddr, v: T) {
        let k = SocketAddr::new(addr, IANA_DNS_PORT_NUMBER);
        let _ = self.entries.insert(k, v);
    }

    /// Adds a rule allowing outbound access to the given IP address and port
    /// number.
    pub fn add_dst(&mut self, addr: SocketAddr, v: T) {
        let _ = self.entries.insert(addr, v);
    }

    /// An iterator over the collection of `SocketAddr` in the ACL.
    pub fn addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.entries.keys()
    }

    /// Returns true if the ACL is empty, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Gets the user supplied data for the given target `SocketAddr`, if any.
    pub fn dst(&self, addr: &SocketAddr) -> Option<&T> {
        self.entries.get(addr)
    }

    /// Gets the user supplied data for the given caller `IpAddr`, if any.
    pub fn src(&self, ip: IpAddr) -> Option<&T> {
        self.entries.get(&SocketAddr::new(ip, IANA_DNS_PORT_NUMBER))
    }

    /// Returns true if the given target `SocketAddr`` exists in this ACL,
    /// false otherwise.
    pub fn has_dst(&self, addr: &SocketAddr) -> bool {
        self.entries.contains_key(addr)
    }

    /// Returns true if the given caller `IpAddr` exists in this ACL, false
    /// otherwise.
    pub fn has_src(&self, ip: IpAddr) -> bool {
        self.entries
            .contains_key(&SocketAddr::new(ip, IANA_DNS_PORT_NUMBER))
    }
}

//------------ XfrStrategy ---------------------------------------------------

/// Which modes of XFR to support.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum XfrStrategy {
    /// Do not support XFR at all.
    #[default]
    None,

    /// Support only AXFR.
    AxfrOnly,

    /// Support only IXFR.
    IxfrOnly,

    /// Support IXFR with fallback to AXFR.
    ///
    /// If IXFR cannot be provided due to missing required incremental
    /// difference data, fallback to full AXFR instead.
    IxfrWithAxfrFallback,
}

//------------ IxfrTransportStrategy -----------------------------------------

/// Which modes of transport to support.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportStrategy {
    #[default]
    None,
    Udp,
    Tcp,
}

//--- Display

impl Display for TransportStrategy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportStrategy::None => f.write_str("None"),
            TransportStrategy::Udp => f.write_str("UDP"),
            TransportStrategy::Tcp => f.write_str("TCP"),
        }
    }
}

//------------ CompatibilityMode ---------------------------------------------

/// https://datatracker.ietf.org/doc/html/rfc5936#section-7.1
/// 7.1.  Server
///   "An implementation of an AXFR server MAY permit configuring, on a per
///    AXFR client basis, the necessity to revert to a single resource record
///    per message; in that case, the default SHOULD be to use multiple
///    records per message."
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum CompatibilityMode {
    #[default]
    Default,

    BackwardCompatible,
}

//------------ TsigKey -------------------------------------------------------

pub type TsigKey = (tsig::KeyName, tsig::Algorithm);

//------------ XfrConfig -----------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct XfrConfig {
    pub strategy: XfrStrategy,
    pub ixfr_transport: TransportStrategy,
    pub compatibility_mode: CompatibilityMode,
    pub tsig_key: Option<TsigKey>,
}

//------------ NotifyConfig --------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct NotifyConfig {
    pub tsig_key: Option<TsigKey>,
}

//------------ Type Aliases --------------------------------------------------

pub type XfrSrcDstConfig = SrcDstConfig<XfrConfig>;
pub type NotifySrcDstConfig = SrcDstConfig<NotifyConfig>;

//------------ NotifyStrategy ------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum NotifyStrategy {
    #[default]
    NotifySourceFirstThenSequentialStoppingAtFirstNewerSerial,
}

//------------ ZoneType ------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct ZoneConfig {
    pub multi_primary_xfr_strategy: NotifyStrategy,
    pub discover_notify_set: bool,
    pub provide_xfr_to: XfrSrcDstConfig,
    pub send_notify_to: NotifySrcDstConfig,
    pub allow_notify_from: NotifySrcDstConfig,
    pub request_xfr_from: XfrSrcDstConfig,
}

impl ZoneConfig {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_primary(
        provide_xfr_to: XfrSrcDstConfig,
        send_notify_to: NotifySrcDstConfig,
    ) -> Self {
        Self {
            provide_xfr_to,
            send_notify_to,
            ..Default::default()
        }
    }

    pub fn new_secondary(
        allow_notify_from: NotifySrcDstConfig,
        request_xfr_from: XfrSrcDstConfig,
    ) -> Self {
        Self {
            allow_notify_from,
            request_xfr_from,
            ..Default::default()
        }
    }
}

impl ZoneConfig {
    pub fn is_primary(&self) -> bool {
        !self.provide_xfr_to.is_empty()
    }

    pub fn is_secondary(&self) -> bool {
        !self.request_xfr_from.is_empty()
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

impl Display for ZoneRefreshStatus {
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
    pub zone_created_at: Instant,

    /// None means never checked
    pub last_refresh_phase_started_at: Option<Instant>,

    /// None means never checked
    pub last_refresh_attempted_at: Option<Instant>,

    /// None means never checked
    pub last_soa_serial_check_succeeded_at: Option<Instant>,

    /// None means never checked
    ///
    /// The SOA SERIAL received for the last successful SOA query sent to a
    /// primary for this zone.
    pub last_soa_serial_check_serial: Option<Serial>,

    /// None means never refreshed
    pub last_refreshed_at: Option<Instant>,

    /// None means never refreshed
    ///
    /// The SOA SERIAL of the last commit made to this zone.
    pub last_refresh_succeeded_serial: Option<Serial>,
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

    pub fn refresh(&self) -> Ttl {
        self.refresh
    }

    pub fn retry(&self) -> Ttl {
        self.retry
    }

    pub fn expire(&self) -> Ttl {
        self.expire
    }

    pub fn status(&self) -> ZoneRefreshStatus {
        self.status
    }

    pub fn set_status(&mut self, status: ZoneRefreshStatus) {
        trace!("Refresh status for zone changed to: {status}");
        self.status = status;
    }

    pub fn metrics(&self) -> ZoneRefreshMetrics {
        self.metrics
    }

    pub fn metrics_mut(&mut self) -> &mut ZoneRefreshMetrics {
        &mut self.metrics
    }

    pub fn is_expired(&self, time_of_last_soa_check: Instant) -> bool {
        Instant::now()
            .checked_duration_since(time_of_last_soa_check)
            .map(|duration_since_last_soa_check| {
                duration_since_last_soa_check > self.expire.into_duration()
            })
            .unwrap_or_default()
    }

    pub fn refresh_succeeded(&mut self, new_soa: &Soa<Name<Bytes>>) {
        self.refresh = new_soa.refresh();
        self.retry = new_soa.retry();
        self.expire = new_soa.expire();
        self.metrics.last_refreshed_at = Some(Instant::now());
        self.metrics.last_refresh_succeeded_serial = Some(new_soa.serial());
        self.set_status(ZoneRefreshStatus::Refreshing);
    }

    pub fn soa_serial_check_succeeded(&mut self, serial: Option<Serial>) {
        if let Some(serial) = serial {
            self.metrics.last_soa_serial_check_serial = Some(serial);
        }
        self.metrics.last_soa_serial_check_succeeded_at =
            Some(Instant::now());
    }

    pub fn age(&self) -> Option<core::time::Duration> {
        self.metrics
            .last_refreshed_at
            .and_then(|at| Instant::now().checked_duration_since(at))
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
pub(super) struct ZoneRefreshInstant {
    pub cause: ZoneRefreshCause,
    pub key: ZoneKey,
    pub end_instant: Instant,
}

impl ZoneRefreshInstant {
    pub fn new(
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
pub(super) enum ZoneRefreshCause {
    ManualTrigger,

    NotifyFromPrimary(IpAddr),

    SoaRefreshTimer,

    SoaRefreshTimerAfterStartup,

    SoaRefreshTimerAfterZoneAdded,

    SoaRetryTimer,
}

impl Display for ZoneRefreshCause {
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

pub(super) struct ZoneRefreshTimer {
    pub refresh_instant: ZoneRefreshInstant,
    pub sleep_fut: Pin<Box<Sleep>>,
}

impl ZoneRefreshTimer {
    pub fn new(refresh_instant: ZoneRefreshInstant) -> Self {
        let sleep_fut = Box::pin(sleep_until(refresh_instant.end_instant));
        Self {
            refresh_instant,
            sleep_fut,
        }
    }

    pub fn deadline(&self) -> Instant {
        self.sleep_fut.deadline()
    }

    pub fn replace(&mut self, new_timer: ZoneRefreshTimer) {
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
pub(super) struct ZoneNameServers {
    pub primary: NameServerNameAddr,
    pub other: Vec<NameServerNameAddr>,
}

impl ZoneNameServers {
    pub fn new(primary_name: StoredName, ips: &[IpAddr]) -> Self {
        let unique_ips = Self::to_socket_addrs(ips);
        let primary = (primary_name, unique_ips);
        Self {
            primary,
            other: vec![],
        }
    }

    pub fn add_ns(&mut self, name: StoredName, ips: &[IpAddr]) {
        let unique_ips = Self::to_socket_addrs(ips);
        self.other.push((name, unique_ips));
    }

    pub fn _primary(&self) -> &NameServerNameAddr {
        &self.primary
    }

    pub fn _others(&self) -> &[NameServerNameAddr] {
        &self.other
    }

    pub fn _addrs(&self) -> impl Iterator<Item = &SocketAddr> {
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
    pub(super) _catalog_member_id: Option<StoredName>,
    pub(super) config: ZoneConfig,
    pub(super) diffs: Arc<Mutex<ZoneDiffs>>,
    pub(super) nameservers: Arc<Mutex<Option<ZoneNameServers>>>,
    pub(super) expired: Arc<AtomicBool>,
}

impl ZoneInfo {
    pub async fn add_diff(&self, diff: ZoneDiff) {
        let k = ZoneDiffKey::new(diff.start_serial, diff.end_serial);
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

    pub fn config(&self) -> &ZoneConfig {
        &self.config
    }

    pub fn expired(&self) -> bool {
        self.expired.load(Ordering::SeqCst)
    }

    pub fn set_expired(&self, expired: bool) {
        self.expired.store(expired, Ordering::SeqCst);
    }
}

//------------ ZoneChangedMsg -------------------------------------------------

#[derive(Debug)]
pub(super) struct ZoneChangedMsg {
    pub class: Class,

    pub apex_name: StoredName,

    // The RFC 1996 section 3.11 known master that was the source of the
    // NOTIFY, if the zone change was learned via an RFC 1996 NOTIFY query.
    pub source: Option<IpAddr>,
}

//------------ ZoneReport ----------------------------------------------------

#[derive(Debug)]
pub struct ZoneReport {
    pub(super) key: ZoneKey,
    pub(super) details: ZoneReportDetails,
    pub(super) timers: Vec<ZoneRefreshInstant>,
    pub(super) zone_info: ZoneInfo,
}

impl ZoneReport {
    pub(super) fn new(
        key: ZoneKey,
        details: ZoneReportDetails,
        timers: Vec<ZoneRefreshInstant>,
        zone_info: ZoneInfo,
    ) -> Self {
        Self {
            key,
            details,
            timers,
            zone_info,
        }
    }
}

//--- Display

impl Display for ZoneReport {
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

impl Display for ZoneReportDetails {
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
pub(super) enum Event {
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
    // TODO?
    //ZoneRemoved(ZoneKey),
}
