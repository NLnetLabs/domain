//! A client cache.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::base::iana::{Class, Opcode, OptRcode, Rtype};
use crate::base::name::ToDname;
use crate::base::Dname;
use crate::base::Message;
use crate::base::MessageBuilder;
use crate::base::ParsedDname;
use crate::base::StaticCompressor;
use crate::base::Ttl;
use crate::dep::octseq::Octets;
use crate::net::client::clock::{Clock, Elapsed, SystemClock};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use crate::rdata::AllRecordData;
use crate::utils::config::DefMinMax;
use bytes::Bytes;
use moka::future::Cache;
use std::boxed::Box;
use std::cmp::min;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

/// Configuration limit for the maximum number of entries in the cache.
const MAX_CACHE_ENTRIES: DefMinMax<u64> =
    DefMinMax::new(1_000, 1, 1_000_000_000);

/// Limit on the maximum time a cache entry is considered valid.
///
/// According to [RFC 8767](https://www.rfc-editor.org/info/rfc8767) the
/// limit should be on the order of days to weeks with a recommended cap of
/// 604800 seconds (7 days).
const MAX_VALIDITY: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(604800),
    Duration::from_secs(60),
    Duration::from_secs(6048000),
);

/// Amount of time to cache transport failures.
///
/// According to [RFC 9520](https://www.rfc-editor.org/info/rfc9520)
/// at least 1 second and at most 5 minutes.
const TRANSPORT_FAILURE_DURATION: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(30),
    Duration::from_secs(1),
    Duration::from_secs(5 * 60),
);

/// Limit on the amount of time to cache DNS result codes that are not
/// NOERROR or NXDOMAIN.
///
/// According to [RFC 9520](https://www.rfc-editor.org/info/rfc9520)
/// at least 1 second and at most 5 minutes.
const MISC_ERROR_DURATION: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(30),
    Duration::from_secs(1),
    Duration::from_secs(5 * 60),
);

/// Limit on the amount of time to cache a NXDOMAIN error.
///
/// According to [RFC 2308](https://www.rfc-editor.org/info/rfc2308)
/// the limit should be one to three hours with a maximum of one day.
const MAX_NXDOMAIN_VALIDITY: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(3600),
    Duration::from_secs(60),
    Duration::from_secs(24 * 3600),
);

/// Limit on the amount of time to cache a NODATA response.
///
/// According to [RFC 2308](https://www.rfc-editor.org/info/rfc2308)
///  the limit should be one to three hours with a maximum of one day.
const MAX_NODATA_VALIDITY: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(3600),
    Duration::from_secs(60),
    Duration::from_secs(24 * 3600),
);

/// Limit on the amount of time a delegation is considered valid.
const MAX_DELEGATION_VALIDITY: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(1_000_000),
    Duration::from_secs(60),
    Duration::from_secs(1_000_000_000),
);

// The following four flags are relevant to caching: AD, CD, DO, and RD.
//
// The AD flag needs to be part of the key when DO is clear. When replying,
// if both AD and DO are not set in the original request then AD needs to be
// cleared if it was set in the response (extra look up if no entry with
// AD clear exists).
//
// The CD flag partitions the cache, responses to request with CD set must not
// be visible to requests with CD clear and vice versa.
//
// A request with DO set can only be satisfied with a response to a request
// with DO set. However, if DO in the request is clear then a response to a
// request with DO set can be used if all unrequested DNSSEC records are
// stripped.
//
// A request with RD clear can be satisfied by a response to a request with
// RD set. For simplicitly requests with RD set will only get a cached
// response to another request with RD set. In theory some responses to
// requests with RD clear could be used to satisfy requests with RD set.
// However, this is not implemented.

// Negative caching is described in RFC 2308
// (https://www.rfc-editor.org/info/rfc2308).
// NXDOMAIN and NODATA require special treatment. NXDOMAIN can be found
// directly in the rcode field. NODATA is the condition where the answer
// section does not contain any record that matches qtype and the message
// is not a referral. NODATA is distinguished from a referral by the presence
// of a SOA record in the authority section (a SOA record present implies
// NODATA). A referral has one or more NS records in the authority section.
// An NXDOMAIN reponse can only be cache if a SOA record is present in the
// authority section. If the SOA record is absent then the NXDOMAIN response
// should not be cached.
// The TTL of the SOA record should reflect how long the response can be
// cached. So no special treatment is needed. Except that a different value
// should limit the maximum time a negative response can be cached.
//
// Caching unreachable upstream should be limited to 5 minutes.
// Caching SERVFAIL should be limited to 5 minutes.

// RFC 8020 (https://www.rfc-editor.org/info/rfc8020) suggests a separate
// <QNAME, QCLASS> cache for NXDOMAIN, but that may be too hard to implement.

// RFC 9520 (https://www.rfc-editor.org/info/rfc9520) requires resolution
// failures to be cached for at least one second. Resolution failure must
// not be cached for longer than 5 minutes.

// RFC 8767 (https://www.rfc-editor.org/info/rfc8767) describes serving stale
// data.

//------------ Config ---------------------------------------------------------

/// Configuration of a cache.
#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum number of cache entries.
    max_cache_entries: u64,

    /// Maximum validity of a normal result.
    max_validity: Duration,

    /// Cache duration of transport failures.
    transport_failure_duration: Duration,

    /// Cache durations of misc. errors. (not NXDOMAIN or NOERROR)
    misc_error_duration: Duration,

    /// Maximum validity of NXDOMAIN results.
    max_nxdomain_validity: Duration,

    /// Maximum validity of NODATA results.
    max_nodata_validity: Duration,

    /// Maximum validity of delegations.
    max_delegation_validity: Duration,
}

impl Config {
    /// Creates a new config with default values.
    ///
    /// The default values are documented at the relevant set_* methods.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the maximum number of cache entries.
    ///
    /// The value has to be at least one, at most 1,000,000,000 and the
    /// default is 1000.
    pub fn set_max_cache_entries(&mut self, value: u64) {
        self.max_cache_entries = MAX_CACHE_ENTRIES.limit(value)
    }

    /// Set the maximum validity of cache entries.
    ///
    /// The value has to be at least 60 seconds, at most 6,048,000 seconds
    /// (10 weeks) and the default is 604800 seconds (one week).
    pub fn set_max_validity(&mut self, value: Duration) {
        self.max_validity = MAX_VALIDITY.limit(value)
    }

    /// Set the time to cache transport failures.
    ///
    /// The value has to be at least one second, at most 300 seconds
    /// (five minutes) and the default is 30 seconds.
    pub fn set_transport_failure_duration(&mut self, value: Duration) {
        self.transport_failure_duration =
            TRANSPORT_FAILURE_DURATION.limit(value)
    }

    /// Set the maximum time to cache results other than NOERROR or NXDOMAIN.
    ///
    /// The value has to be at least one second, at most 300 seconds
    /// (five minutes) and the default is 30 seconds.
    pub fn set_misc_error_duration(&mut self, value: Duration) {
        self.misc_error_duration = MISC_ERROR_DURATION.limit(value)
    }

    /// Set the maximum time to cache NXDOMAIN results.
    ///
    /// The value has to be at least 60 seconds (one minute), at most 86,400
    /// seconds (one day) and the default is 3,600 seconds (one hour).
    pub fn set_max_nxdomain_validity(&mut self, value: Duration) {
        self.max_nxdomain_validity = MAX_NXDOMAIN_VALIDITY.limit(value)
    }

    /// Set the maximum time to cache NODATA results.
    ///
    /// The value has to be at least 60 seconds (one minute), at most 86,400
    /// seconds (one day) and the default is 3,600 seconds (one hour).
    pub fn set_max_nodata_validity(&mut self, value: Duration) {
        self.max_nodata_validity = MAX_NODATA_VALIDITY.limit(value)
    }

    /// Set the maximum time to cache delegations.
    ///
    /// The value has to be at least 60 seconds (one minute), at most
    /// 1,000,000,000 seconds and the default is 1,000,000 seconds.
    pub fn set_max_delegation_validity(&mut self, value: Duration) {
        self.max_delegation_validity = MAX_DELEGATION_VALIDITY.limit(value)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_cache_entries: MAX_CACHE_ENTRIES.default(),
            max_validity: MAX_VALIDITY.default(),
            transport_failure_duration: TRANSPORT_FAILURE_DURATION.default(),
            misc_error_duration: MISC_ERROR_DURATION.default(),
            max_nxdomain_validity: MAX_NXDOMAIN_VALIDITY.default(),
            max_nodata_validity: MAX_NODATA_VALIDITY.default(),
            max_delegation_validity: MAX_DELEGATION_VALIDITY.default(),
        }
    }
}

//------------ Connection -----------------------------------------------------

#[derive(Clone)]
/// A connection that caches responses from an upstream connection.
pub struct Connection<Upstream, C: Clock + Send + Sync = SystemClock> {
    /// Upstream transport to use for requests.
    upstream: Upstream,

    /// The cache for this connection.
    cache: Cache<Key, Arc<Value<C>>>,

    /// The configuration of this connection.
    config: Config,

    /// The clock to use for expiring cache entries.
    clock: C,
}

impl<Upstream> Connection<Upstream> {
    /// Create a new connection with default configuration parameters.
    pub fn new(upstream: Upstream) -> Self {
        Self::with_config(upstream, Default::default())
    }

    /// Create a new connection with specified configuration parameters.
    pub fn with_config(upstream: Upstream, config: Config) -> Self {
        Self {
            upstream,
            cache: Cache::new(config.max_cache_entries),
            config,
            clock: SystemClock::new(),
        }
    }
}

impl<Upstream, C> Connection<Upstream, C>
where
    C: Clock + Send + Sync + 'static,
{
    /// Create a new connection with default configuration parameters.
    pub fn new_with_time(upstream: Upstream, clock: C) -> Self {
        Self::with_time_config(upstream, clock, Default::default())
    }

    /// Create a new connection with specified configuration parameters.
    pub fn with_time_config(
        upstream: Upstream,
        clock: C,
        config: Config,
    ) -> Self {
        Self {
            upstream,
            cache: Cache::new(config.max_cache_entries),
            config,
            clock,
        }
    }
}

//------------ SendRequest ----------------------------------------------------

impl<CR, Upstream, C> SendRequest<CR> for Connection<Upstream, C>
where
    CR: Clone + ComposeRequest + 'static,
    Upstream: Clone + SendRequest<CR> + Send + Sync + 'static,
    C: Clock + Debug + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request::<CR, Upstream, C>::new(
            request_msg,
            self.upstream.clone(),
            self.cache.clone(),
            self.config.clone(),
            self.clock.clone(),
        ))
    }
}

//------------ Request --------------------------------------------------------

/// The state of a request that is executed.
pub struct Request<CR, Upstream, C>
where
    CR: Send + Sync,
    Upstream: Send + Sync,
    C: Clock + Send + Sync,
{
    /// State of the request.
    state: RequestState,

    /// The request message.
    request_msg: CR,

    /// The upstream transport of the connection.
    upstream: Upstream,

    /// The cache of the connection.
    cache: Cache<Key, Arc<Value<C>>>,

    /// The configuration of the connection.
    config: Config,

    /// The clock to use for expiring cache entries.
    clock: C,
}

impl<CR, Upstream, C> Request<CR, Upstream, C>
where
    CR: Clone + ComposeRequest + Send + Sync,
    Upstream: SendRequest<CR> + Send + Sync,
    C: Clock + Debug + Send + Sync + 'static,
{
    /// Create a new Request object.
    fn new(
        request_msg: CR,
        upstream: Upstream,
        cache: Cache<Key, Arc<Value<C>>>,
        config: Config,
        clock: C,
    ) -> Request<CR, Upstream, C> {
        Self {
            state: RequestState::Init,
            request_msg,
            upstream,
            cache,
            config,
            clock,
        }
    }

    /// This is the implementation of the get_response method.
    ///
    /// This function is cancel safe.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        loop {
            match &mut self.state {
                RequestState::Init => {
                    let msg = self.request_msg.to_message()?;
                    let header = msg.header();
                    let opcode = header.opcode();

                    // Extract Qname, Qclass, Qtype
                    let mut question_section = msg.question();
                    let question = match question_section.next() {
                        None => {
                            // No question. Just forward the request.
                            let request = self
                                .upstream
                                .send_request(self.request_msg.clone());
                            self.state =
                                RequestState::GetResponseNoCache(request);
                            continue;
                        }
                        Some(question) => question?,
                    };
                    if question_section.next().is_some() {
                        // More than one question. Just forward the request.
                        let request = self
                            .upstream
                            .send_request(self.request_msg.clone());
                        self.state =
                            RequestState::GetResponseNoCache(request);
                        continue;
                    }
                    let qname = question.qname();
                    let qclass = question.qclass();
                    let qtype = question.qtype();

                    if !(opcode == Opcode::Query && qclass == Class::In) {
                        // Anything other than a query on the Internet class
                        // should not be cached.
                        let request = self
                            .upstream
                            .send_request(self.request_msg.clone());
                        self.state =
                            RequestState::GetResponseNoCache(request);
                        continue;
                    }

                    let mut ad = header.ad();
                    let cd = header.cd();
                    let rd = header.rd();

                    let dnssec_ok =
                        msg.opt().map_or(false, |opt| opt.dnssec_ok());
                    if dnssec_ok && !ad {
                        ad = true;
                    }

                    let key =
                        Key::new(qname, qclass, qtype, ad, cd, dnssec_ok, rd);
                    let opt_ce = self.cache_lookup(&key).await?;
                    if let Some(value) = opt_ce {
                        let opt_response =
                            handle_cache_value::<_, C>(qname, value);
                        if let Some(response) = opt_response {
                            return response;
                        }
                    }

                    let request =
                        self.upstream.send_request(self.request_msg.clone());
                    self.state = RequestState::GetResponse(key, request);
                    continue;
                }
                RequestState::GetResponse(key, request) => {
                    let response = request.get_response().await;

                    let key = key.clone();
                    let value = Arc::new(Value::new(
                        response.clone(),
                        &self.config,
                        &self.clock,
                    )?);
                    self.cache_insert(key, value).await;

                    return response;
                }
                RequestState::GetResponseNoCache(request) => {
                    return request.get_response().await;
                }
            }
        }
    }

    /// Try to find a cache entry for the key.
    async fn cache_lookup(
        &self,
        key: &Key,
    ) -> Result<Option<Arc<Value<C>>>, Error> {
        // There are 4 flags that may affect the response to a query.
        // In some cases the response to one value of a flag could be
        // used for the other value.
        // This function takes all 4 flags. First we take care of the CD flag.
        // This flag has to be used as is, so there is not much to do. Next
        // we pass the request to a function that looks at RD, DO, and AD.
        self.cache_lookup_rd_do_ad(key).await
    }

    /// Try to find an cache entry for the key taking into account the
    /// RD, DO, and AD flags. The CD flag is kept unchanged.
    async fn cache_lookup_rd_do_ad(
        &self,
        key: &Key,
    ) -> Result<Option<Arc<Value<C>>>, Error> {
        // For RD=1 we can only use responses to queries with RD set.
        // For RD=0, first try with RD=0 and then try with RD=1. If
        // RD=1 has an answer, store it as an answer for RD=0.
        let opt_value = self.cache_lookup_do_ad(key).await?;
        if opt_value.is_some() || key.rd {
            return Ok(opt_value);
        }

        // Look if there is something with RD=1. We can use the
        // response unmodified.
        let mut alt_key = key.clone();
        alt_key.rd = true;
        let opt_value = self.cache_lookup_do_ad(&alt_key).await?;
        if let Some(value) = &opt_value {
            match &value.response {
                Err(_) => {
                    // Just insert the error
                    self.cache_insert(key.clone(), value.clone()).await;
                }
                Ok(msg) => {
                    let msg = clear_rd(msg)?;
                    let value =
                        Arc::new(Value::<C>::new_from_value_and_response(
                            value.clone(),
                            Ok(msg),
                            &self.config,
                        )?);
                    self.cache_insert(key.clone(), value.clone()).await;
                    return Ok(Some(value));
                }
            }
        }
        Ok(opt_value)
    }

    /// Try to find an cache entry for the key taking into account the
    /// DO and AD flags. The CD and RD flags are kept unchanged.
    async fn cache_lookup_do_ad(
        &self,
        key: &Key,
    ) -> Result<Option<Arc<Value<C>>>, Error> {
        // For DO=1 we can only use responses to queries with DO set.
        // For DO=0, first try with DO=0 and then try with DO=1. If
        // DO=1 has an answer, remove DNSSEC related resource records.
        // If AD is clear then clear the AD bit.

        // If DO is set then AD is irrelevant. Force AD to be set for
        // consistency (if DO is set then with respect to the AD flag
        // the behavior is as if AD is set).

        if key.dnssec_ok {
            assert!(key.ad);
        }

        let opt_value = self.cache_lookup_ad(key).await?;
        if opt_value.is_some() || key.dnssec_ok {
            return Ok(opt_value);
        }

        if is_dnssec(key.qtype) {
            // An explicit request for one of the DNSSEC types but
            // DO is not set. Force the request to be sent explicitly.
            return Ok(None);
        }

        let mut alt_key = key.clone();
        alt_key.dnssec_ok = true;
        alt_key.ad = true;
        let opt_value = self.cache.get(&alt_key).await;
        if let Some(value) = &opt_value {
            match &value.response {
                Err(_) => {
                    // Just insert the error
                    self.cache_insert(key.clone(), value.clone()).await;
                }
                Ok(msg) => {
                    let msg = remove_dnssec(msg, key.ad)?;
                    let value =
                        Arc::new(Value::<C>::new_from_value_and_response(
                            value.clone(),
                            Ok(msg),
                            &self.config,
                        )?);
                    self.cache_insert(key.clone(), value.clone()).await;
                    return Ok(Some(value));
                }
            }
        }
        Ok(opt_value)
    }

    /// Try to find an cache entry for the key taking into account the
    /// AD flag. The CD, DO, and RD flags are kept unchanged.
    async fn cache_lookup_ad(
        &self,
        key: &Key,
    ) -> Result<Option<Arc<Value<C>>>, Error> {
        // For AD=1 we can only use responses to queries with AD set.
        // For AD=0, first try with AD=0 and then try with AD=1. If
        // AD=1 has an answer, clear the AD bit.
        let opt_value = self.cache.get(key).await;
        if opt_value.is_some() || key.ad {
            return Ok(opt_value);
        }
        let mut alt_key = key.clone();
        alt_key.ad = true;
        let opt_value = self.cache.get(&alt_key).await;
        if let Some(value) = &opt_value {
            match &value.response {
                Err(_) => {
                    // Just insert the error
                    self.cache_insert(key.clone(), value.clone()).await;
                }
                Ok(msg) => {
                    if !msg.header().ad() {
                        // AD is clear. Just insert this value.
                        self.cache_insert(key.clone(), value.clone()).await;
                        return Ok(Some(value.clone()));
                    }

                    let msg = clear_ad(msg)?;
                    let value =
                        Arc::new(Value::<C>::new_from_value_and_response(
                            value.clone(),
                            Ok(msg),
                            &self.config,
                        )?);
                    self.cache_insert(key.clone(), value.clone()).await;
                    return Ok(Some(value));
                }
            }
        }
        Ok(opt_value)
    }

    /// Insert new entry in the cache.
    ///
    /// Do not insert if the validity is zero.
    /// Make sure to clear the AA flag.
    async fn cache_insert(&self, key: Key, value: Arc<Value<C>>) {
        if value.valid_for.is_zero() {
            // Do not insert cache value that are valid for zero duration.
            return;
        }
        let value = match prepare_for_insert(value.clone(), &self.config) {
            Ok(value) => value,
            Err(e) => {
                // Create a new value based on this error
                Arc::new(
                    Value::<C>::new_from_value_and_response(
                        value,
                        Err(e),
                        &self.config,
                    )
                    .expect("value from error does not fail"),
                )
            }
        };
        self.cache.insert(key, value).await
    }
}

impl<CR, Upstream, C> Debug for Request<CR, Upstream, C>
where
    CR: Send + Sync,
    Upstream: Send + Sync,
    C: Clock + Send + Sync,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

impl<CR, Upstream, C> GetResponse for Request<CR, Upstream, C>
where
    CR: Clone + ComposeRequest + Debug + Sync,
    Upstream: SendRequest<CR> + Send + Sync + 'static,
    C: Clock + Debug + Send + Sync + 'static,
{
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Message<Bytes>, Error>>
                + Send
                + Sync
                + '_,
        >,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ RequestState ---------------------------------------------------
/// States of the state machine in get_response_impl
enum RequestState {
    /// Initial state, perform a cache lookup.
    Init,

    /// Wait for a response and insert the response in the cache.
    GetResponse(Key, Box<dyn GetResponse + Send + Sync>),

    /// Wait for a response but do not insert the response in the cache.
    GetResponseNoCache(Box<dyn GetResponse + Send + Sync>),
}

//------------ Key ------------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
/// The key for cache entries.
struct Key {
    /// DNS name in the request.
    qname: Dname<Vec<u8>>,

    /// The request class. Always IN at the moment.
    qclass: Class,

    /// The requested type.
    qtype: Rtype,

    /// Value of the AD flag.
    ad: bool,

    /// Value of the CD flag.
    cd: bool,

    /// Value of the DO flag.
    dnssec_ok: bool,

    /// Value of the RD flag.
    rd: bool,
}

impl Key {
    /// Create a new key object.
    fn new<TDN>(
        qname: TDN,
        qclass: Class,
        qtype: Rtype,
        ad: bool,
        cd: bool,
        dnssec_ok: bool,
        rd: bool,
    ) -> Key
    where
        TDN: ToDname,
    {
        let mut qname = qname.to_dname().expect("to_dname should not fail");

        // Make sure qname is canonical.
        qname.make_canonical();

        Self {
            qname,
            qclass,
            qtype,
            ad,
            cd,
            dnssec_ok,
            rd,
        }
    }
}

//------------ Value ----------------------------------------------------------

#[derive(Debug)]
/// The value to be cached.
struct Value<C>
where
    C: Clock + Send + Sync,
{
    /// Creation time of the cache entry.
    created_at: C::Instant,

    /// The amount time the cache entry is valid.
    valid_for: Duration,

    /// The cached response.
    response: Result<Message<Bytes>, Error>,
}

impl<C> Value<C>
where
    C: Clock + Send + Sync,
{
    /// Create a new value object.
    fn new(
        response: Result<Message<Bytes>, Error>,
        config: &Config,
        clock: &C,
    ) -> Result<Value<C>, Error> {
        Ok(Self {
            created_at: clock.now(),
            valid_for: validity(&response, config)?,
            response,
        })
    }

    /// Create a value object that is derived from another value object.
    fn new_from_value_and_response(
        val: Arc<Value<C>>,
        response: Result<Message<Bytes>, Error>,
        config: &Config,
    ) -> Result<Value<C>, Error> {
        Ok(Self {
            created_at: val.created_at.clone(),
            valid_for: validity(&response, config)?,
            response,
        })
    }
}

//------------ Utility functions ----------------------------------------------

/// Handle a cached value. Either return None if the value has expired or
/// return a response message with decremented TTL values.
fn handle_cache_value<TDN, C>(
    orig_qname: TDN,
    value: Arc<Value<C>>,
) -> Option<Result<Message<Bytes>, Error>>
where
    TDN: ToDname + Clone,
    C: Clock + Send + Sync,
{
    let elapsed = value.created_at.elapsed();
    if elapsed > value.valid_for {
        return None;
    }
    let secs = elapsed.as_secs() as u32;
    let response = decrement_ttl(orig_qname, &value.response, secs);
    Some(response)
}

/// Compute how long a response can be cached.
fn validity(
    response: &Result<Message<Bytes>, Error>,
    config: &Config,
) -> Result<Duration, Error> {
    let Ok(msg) = response else {
        return Ok(config.transport_failure_duration);
    };

    let mut min_val = config.max_validity;

    match get_opt_rcode(msg) {
        OptRcode::NoError => {
            match classify_no_error(msg)? {
                NoErrorType::Answer => (),
                NoErrorType::NoData => {
                    min_val = min(min_val, config.max_nodata_validity)
                }
                NoErrorType::Delegation => {
                    min_val = min(min_val, config.max_delegation_validity)
                }
                NoErrorType::NoErrorWeird =>
                // Weird NODATA response. Don't cache this.
                {
                    min_val = Duration::from_secs(0)
                }
            }
        }
        OptRcode::NXDomain => {
            min_val = min(min_val, config.max_nxdomain_validity);
        }

        _ => {
            min_val = min(min_val, config.misc_error_duration);
        }
    }

    let msg = msg.question();
    let mut msg = msg.answer()?;
    for rr in &mut msg {
        let rr = rr?;
        min_val =
            min(min_val, Duration::from_secs(rr.ttl().as_secs() as u64));
    }

    let mut msg = msg.next_section()?.expect("section should be present");
    for rr in &mut msg {
        let rr = rr?;
        min_val =
            min(min_val, Duration::from_secs(rr.ttl().as_secs() as u64));
    }

    let msg = msg.next_section()?.expect("section should be present");
    for rr in msg {
        let rr = rr?;
        if rr.rtype() != Rtype::Opt {
            min_val =
                min(min_val, Duration::from_secs(rr.ttl().as_secs() as u64));
        }
    }

    Ok(min_val)
}

/// Return a new message with decremented TTL values.
fn decrement_ttl<TDN>(
    orig_qname: TDN,
    response: &Result<Message<Bytes>, Error>,
    amount: u32,
) -> Result<Message<Bytes>, Error>
where
    TDN: ToDname + Clone,
{
    let msg = match response {
        Err(err) => return Err(err.clone()),
        Ok(msg) => msg,
    };

    let amount = Ttl::from_secs(amount);

    let mut target =
        MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
            .expect("Vec is expected to have enough space");

    let source = msg;

    *target.header_mut() = source.header();

    let source = source.question();
    let mut target = target.question();
    for rr in source {
        let rr = rr?;
        target
            .push((orig_qname.clone(), rr.qtype(), rr.qclass()))
            .expect("push failed");
    }
    let mut source = source.answer()?;
    let mut target = target.answer();
    for rr in &mut source {
        let mut rr = rr?
            .into_record::<AllRecordData<_, ParsedDname<_>>>()?
            .expect("record expected");
        rr.set_ttl(rr.ttl() - amount);
        target.push(rr).expect("push failed");
    }

    let mut source =
        source.next_section()?.expect("section should be present");
    let mut target = target.authority();
    for rr in &mut source {
        let mut rr = rr?
            .into_record::<AllRecordData<_, ParsedDname<_>>>()?
            .expect("record expected");
        rr.set_ttl(rr.ttl() - amount);
        target.push(rr).expect("push failed");
    }

    let source = source.next_section()?.expect("section should be present");
    let mut target = target.additional();
    for rr in source {
        let rr = rr?;
        let mut rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()?
            .expect("record expected");
        if rr.rtype() != Rtype::Opt {
            rr.set_ttl(rr.ttl() - amount);
        }
        target.push(rr).expect("push failed");
    }

    let result = target.as_builder().clone();
    let msg =
        Message::<Bytes>::from_octets(result.finish().into_target().into())
            .expect(
                "Message should be able to parse output from MessageBuilder",
            );
    Ok(msg)
}

/// Return a new message without the DNSSEC type RRSIG, NSEC, and NSEC3.
fn remove_dnssec(
    msg: &Message<Bytes>,
    ad: bool,
) -> Result<Message<Bytes>, Error> {
    let mut target =
        MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
            .expect("Vec is expected to have enough space");

    let source = msg;

    *target.header_mut() = source.header();

    if !ad {
        // Clear ad
        target.header_mut().set_ad(false);
    }

    let source = source.question();
    let mut target = target.question();
    for rr in source {
        target.push(rr?).expect("push failed");
    }
    let mut source = source.answer()?;
    let mut target = target.answer();
    for rr in &mut source {
        let rr = rr?
            .into_record::<AllRecordData<_, ParsedDname<_>>>()?
            .expect("record expected");
        if is_dnssec(rr.rtype()) {
            continue;
        }
        target.push(rr).expect("push error");
    }

    let mut source =
        source.next_section()?.expect("section should be present");
    let mut target = target.authority();
    for rr in &mut source {
        let rr = rr?
            .into_record::<AllRecordData<_, ParsedDname<_>>>()?
            .expect("record expected");
        if is_dnssec(rr.rtype()) {
            continue;
        }
        target.push(rr).expect("push error");
    }

    let source = source.next_section()?.expect("section should be present");
    let mut target = target.additional();
    for rr in source {
        let rr = rr?;
        let rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()?
            .expect("record expected");
        if is_dnssec(rr.rtype()) {
            continue;
        }
        target.push(rr).expect("push error");
    }

    let result = target.as_builder().clone();
    Ok(
        Message::<Bytes>::from_octets(result.finish().into_target().into())
            .expect(
                "Message should be able to parse output from MessageBuilder",
            ),
    )
}

/// Check if a type is a DNSSEC type that needs to be removed.
fn is_dnssec(rtype: Rtype) -> bool {
    rtype == Rtype::Rrsig || rtype == Rtype::Nsec || rtype == Rtype::Nsec3
}

/// This type represents that various subtypes of a NOERROR result.
enum NoErrorType {
    /// The result is an answer to the question.
    Answer,

    /// The name exists, but there is not data for the request class and tpye
    /// combination.
    NoData,

    /// The upstream DNS server sent a delegation to another DNS zone.
    Delegation,

    /// None of the above. This is not a valid response.
    NoErrorWeird,
}

/// Classify a responses with a NOERROR result.
fn classify_no_error<Octs>(msg: &Message<Octs>) -> Result<NoErrorType, Error>
where
    Octs: Octets,
{
    // Check if we have something that resembles an answer.
    let mut question_section = msg.question();
    let question = question_section.next().expect("section expected")?;
    let qtype = question.qtype();
    let qclass = question.qclass();

    // Note we only look qtype and qclass. The goal is not to perform
    // a consistency check. Just whether there is supposed to be an
    // answer or not.
    let mut msg = msg.answer()?;
    for rr in &mut msg {
        let rr = rr?;
        if rr.rtype() == qtype && rr.class() == qclass {
            // We found an answer.
            return Ok(NoErrorType::Answer);
        }
    }

    // No answer. Check the authority section for SOA and NS records.
    // If the SOA is present then the response is a NODATA response.
    // If SOA records are absent but NS records are present then the
    // response is a delegation.
    let mut found_ns = false;
    let mut msg = msg.next_section()?.expect("section should be present");
    for rr in &mut msg {
        let rr = rr?;
        if rr.class() == qclass && rr.rtype() == Rtype::Soa {
            return Ok(NoErrorType::NoData);
        }
        if rr.class() == qclass && rr.rtype() == Rtype::Ns {
            found_ns = true;
        }
    }

    if found_ns {
        return Ok(NoErrorType::Delegation);
    }

    // Neither SOA nor NS were found. This is a broken response.
    Ok(NoErrorType::NoErrorWeird)
}

/// Get the extended rcode of a message.
fn get_opt_rcode<Octs: Octets>(msg: &Message<Octs>) -> OptRcode {
    msg.opt()
        .map(|opt| opt.rcode(msg.header()))
        .unwrap_or_else(|| msg.header().rcode().into())
}

/// Return a message with the AA flag clear.
fn clear_aa(msg: &Message<Bytes>) -> Result<Message<Bytes>, Error> {
    // Assume the clear_aa will be called only if AA is set. So no need to
    // optimize for the case where AA is clear.
    let mut msg = Message::<Vec<u8>>::from_octets(msg.as_slice().into())?;
    let hdr = msg.header_mut();
    hdr.set_aa(false);
    Ok(Message::<Bytes>::from_octets(msg.into_octets().into())?)
}

/// Return a message with the AD flag clear.
fn clear_ad(msg: &Message<Bytes>) -> Result<Message<Bytes>, Error> {
    // Assume the clear_ad will be called only if AD is set. So no need to
    // optimize for the case where AD is clear.
    let mut msg = Message::<Vec<u8>>::from_octets(msg.as_slice().into())?;
    let hdr = msg.header_mut();
    hdr.set_ad(false);
    Ok(Message::<Bytes>::from_octets(msg.into_octets().into())?)
}

/// Return a message with the RD flag clear.
fn clear_rd(msg: &Message<Bytes>) -> Result<Message<Bytes>, Error> {
    // Assume the clear_rd will be called only if RD is set. So no need to
    // optimize for the case where RD is clear.
    let mut msg = Message::<Vec<u8>>::from_octets(msg.as_slice().into())?;
    let hdr = msg.header_mut();
    hdr.set_rd(false);
    Ok(Message::<Bytes>::from_octets(msg.into_octets().into())?)
}

/// Prepare a value for inserting in the cache by clearing the AA flag if
/// set.
fn prepare_for_insert<C>(
    value: Arc<Value<C>>,
    config: &Config,
) -> Result<Arc<Value<C>>, Error>
where
    C: Clock + Send + Sync,
{
    Ok(match &value.response {
        Err(_) => {
            // Just insert the error
            value
        }
        Ok(msg) => {
            if msg.header().aa() {
                let msg = clear_aa(msg)?;
                Arc::new(Value::<C>::new_from_value_and_response(
                    value.clone(),
                    Ok(msg),
                    config,
                )?)
            } else {
                // AA is clear. Just insert this value.
                value
            }
        }
    })
}
