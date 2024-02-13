//! A client cache.

//#![warn(missing_docs)]
//#![warn(clippy::missing_docs_in_private_items)]

use crate::base::iana::{Class, Opcode, OptRcode, Rtype};
use crate::base::name::ToDname;
use crate::base::Dname;
use crate::base::Message;
use crate::base::MessageBuilder;
use crate::base::ParsedDname;
use crate::base::StaticCompressor;
use crate::base::Ttl;
use crate::dep::octseq::Octets;
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use crate::net::client::time::{Elapsed, SimpleTime, Time};
use crate::rdata::AllRecordData;
use bytes::Bytes;
use moka::future::Cache;
use std::boxed::Box;
use std::cmp::min;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

const MAX_CACHE_ENTRIES: u64 = 10_000;

const MAX_VALIDITY: u32 = 1_000_000;

// Min 1 second, max 5 minutes
const DEF_TRANSPORT_FAILURE_DURATION: Duration = Duration::from_secs(30);

// Min 1 second, max 5 minutes
const DEF_MISC_ERROR_TTL: u32 = 30;

const DEF_NXDOMAIN_TTL: u32 = 24 * 3600;
const DEF_NODATA_TTL: u32 = 24 * 3600;
const DEF_DELEGATION_TTL: u32 = 24 * 3600;

// The following four flags are relevant to caching: AD, CD, DO, and RD.
//
// The AD flag needs to be part of the key when DO is clear. When replying,
// if both AD and DO are not set in the original request then AD needs to be
// cleared if it was set in the response (extra look up if no entry with
// AD clear exists.
//
// The CD flag partitions the cache, responses to request with CD set must not
// be visible to requests with CD and vice versa.
//
// A request with DO set can only be satisfied with a response to a request
// with CD set. However, if CD in the request is clear then a reponse to a
// request with CD set can be used if all unrequested DNSSEC records are
// stripped.
//
// A request with RD clear can be satisfied by a response to a request with
// RD set. For simplicitly requests with RD set can only get a response to
// a request with RD set. In theory some responses to requests with RD clear
// could satisfy requests with RD set.

// Negative caching is described in RFC 2308.
// NXDOMAIN and NODATA require special treatment. NXDOMAIN can be found
// directly in the rcode field. NODATA is the condition where the answer
// section does not contain any record that matches qtype and the message
// is not a referral. NODATA is distinguished for a referral by the presence
// of a SOA record in the authority section (a SOA record present implies
// NODATA). A referral has one or more NS records in the authority section.
// A NXDOMAIN reponse can only be cache if a SOA record is present in the
// authority section. If the SOA record is absent then the NXDOMAIN response
// should not be cached.
// The TTL of the SOA record should reflect how long the response can be
// cached. So no special treat is needed. Except that a different value should
// limit the maximum time a negative response can be cached.
//
// Caching unreachable upstream should be limited to 5 minutes.
// Caching SERVFAIL should be limited to 5 minutes.

// RFC 8020 suggests a separate <QNAME, QCLASS> cache for NXDOMAIN, but
// that may be too hard to implement.

// RFC 9520 requires resolution failures to be cached for at least one
// second. Resolution failure must not be cached for longer than 5 minutes.

// RFC 8767 describes serving stale data.

//------------ Config ---------------------------------------------------------

/// Configuration of a cache.
#[derive(Clone, Debug, Default)]
pub struct Config {}

impl Config {
    /// Creates a new config with default values.
    pub fn new() -> Self {
        Default::default()
    }
}

/*
impl Default for Config {
    fn default() -> Self {
        Self {}
    }
}
*/

//------------ Connection -----------------------------------------------------

#[derive(Clone)]
/// A connection that cache response from an upstream connection.
pub struct Connection<Upstream, T: Send + Sync + Time = SimpleTime> {
    upstream: Upstream,
    cache: Cache<Key, Arc<Value<T>>>,
    _phantom: PhantomData<T>,
}

impl<Upstream> Connection<Upstream> {
    /// Create a new connection with default configuration parameters.
    pub fn new(upstream: Upstream) -> Self {
        Self::with_config(upstream, Default::default())
    }

    /// Create a new connection with specified configuration parameters.
    pub fn with_config(upstream: Upstream, _config: Config) -> Self {
        Self {
            upstream,
            cache: Cache::new(MAX_CACHE_ENTRIES),
            _phantom: PhantomData,
        }
    }
}

impl<Upstream, T> Connection<Upstream, T>
where
    T: Send + Sync + Time + 'static,
{
    /// Create a new connection with default configuration parameters.
    pub fn new_with_time(upstream: Upstream) -> Self {
        Self::with_time_config(upstream, Default::default())
    }

    /// Create a new connection with specified configuration parameters.
    pub fn with_time_config(upstream: Upstream, _config: Config) -> Self {
        Self {
            upstream,
            cache: Cache::new(MAX_CACHE_ENTRIES),
            _phantom: PhantomData,
        }
    }
}

impl<Upstream> Debug for Connection<Upstream> {
    fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        todo!()
    }
}

//------------ SendRequest ----------------------------------------------------

impl<CR, Upstream, T> SendRequest<CR> for Connection<Upstream, T>
where
    CR: Clone + ComposeRequest + 'static,
    Upstream: Clone + SendRequest<CR> + Send + Sync + 'static,
    T: Debug + Time + Send + Sync + 'static,
{
    fn send_request(&self, request_msg: CR) -> Box<dyn GetResponse + Send> {
        Box::new(Request::<CR, Upstream, T>::new(
            request_msg,
            self.upstream.clone(),
            self.cache.clone(),
        ))
    }
}

//------------ Request --------------------------------------------------------

/// The state of a request that is executed.
pub struct Request<CR, Upstream, T>
where
    CR: Send + Sync,
    Upstream: Send + Sync,
    T: Send + Sync + Time,
{
    request_msg: CR,
    upstream: Upstream,
    cache: Cache<Key, Arc<Value<T>>>,
    _phantom: PhantomData<T>,
}

impl<CR, Upstream, T> Request<CR, Upstream, T>
where
    CR: Clone + ComposeRequest + Send + Sync,
    Upstream: SendRequest<CR> + Send + Sync,
    T: Debug + Send + Sync + Time + 'static,
{
    fn new(
        request_msg: CR,
        upstream: Upstream,
        cache: Cache<Key, Arc<Value<T>>>,
    ) -> Request<CR, Upstream, T> {
        Self {
            request_msg,
            upstream,
            cache,
            _phantom: PhantomData,
        }
    }

    // XXX Note that function has to be cancel safe but isn't
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        println!("get_response_impl: starting");
        let msg = self.request_msg.to_message();
        let header = msg.header();
        let opcode = header.opcode();

        // Extract Qname, Qclass, Qtype
        let mut question_section = msg.question();
        let question = question_section.next().unwrap().unwrap();
        if question_section.next().is_some() {
            panic!("should handle multiple questions");
        }
        let qname = question.qname();
        let qclass = question.qclass();
        let qtype = question.qtype();

        if !(opcode == Opcode::Query && qclass == Class::In) {
            // Anything other than a query on the Internet class
            // should not be cached.
            let mut request =
                self.upstream.send_request(self.request_msg.clone());
            return request.get_response().await;
        }

        println!("get_reponse_impl: got {qname} {qclass} {qtype}");
        let mut ad = header.ad();
        let cd = header.cd();
        let rd = header.rd();

        let dnssec_ok = if let Some(opt) = msg.opt() {
            opt.dnssec_ok()
        } else {
            false
        };
        if dnssec_ok && !ad {
            ad = true;
        }
        println!("get_reponse_impl: ad {ad}, cd {cd}, rd {rd}, dnssec_ok {dnssec_ok}");

        let key = Key::new(qname, qclass, qtype, ad, cd, dnssec_ok, rd);
        let opt_ce = self.cache_lookup(&key).await;
        println!("get_response_impl: opt_ce {opt_ce:?}");
        if let Some(value) = opt_ce {
            let opt_response = handle_cache_value(qname, value);
            println!("get_response_impl: opt_response {opt_response:?}");
            if let Some(response) = opt_response {
                println!("get_response_impl: returning cached response {response:?}");
                return response;
            }
        }

        let mut request =
            self.upstream.send_request(self.request_msg.clone());
        let response = request.get_response().await;

        let value = Arc::new(Value::<T>::new(&response));
        self.cache_insert(key, value).await;

        response
    }

    async fn cache_lookup(&self, key: &Key) -> Option<Arc<Value<T>>> {
        // There are 4 flags that may affect the response to a query.
        // In some cases the response to one value of a flag could be
        // used for the ohter value.
        // This function takes all 4 flags. First we fix the CD flag.
        // This flag has to be used as is. Next we have the request to
        // a function that looks at RD, DO, and AD.
        self.cache_lookup_rd_do_ad(key).await
    }

    async fn cache_lookup_rd_do_ad(
        &self,
        key: &Key,
    ) -> Option<Arc<Value<T>>> {
        // For RD=1 we can only use responses to queries with RD set.
        // For RD=0, first try with RD=0 and then try with RD=1. If
        // RD=1 has an answer, store it as an answer for RD=0.
        let opt_value = self.cache_lookup_do_ad(key).await;
        if opt_value.is_some() || key.rd {
            return opt_value;
        }

        // Look if there is something with RD=1. We can use the
        // response unmodified.
        let mut alt_key = key.clone();
        alt_key.rd = true;
        println!("cache_lookup_rd_do_ad: alt {alt_key:?}");
        let opt_value = self.cache_lookup_do_ad(&alt_key).await;
        println!("cache_lookup_rd_do_ad: cached alt value {opt_value:?}");
        if let Some(value) = &opt_value {
            match &value.response {
                Err(_) => {
                    // Just insert the error
                    self.cache_insert(key.clone(), value.clone()).await;
                }
                Ok(msg) => {
                    let msg = clear_rd(msg);
                    let value =
                        Arc::new(Value::<T>::new_from_value_and_response(
                            value.clone(),
                            Ok(msg),
                        ));
                    self.cache_insert(key.clone(), value.clone()).await;
                    return Some(value);
                }
            }
        }
        opt_value
    }

    async fn cache_lookup_do_ad(&self, key: &Key) -> Option<Arc<Value<T>>> {
        // For DO=1 we can only use responses to queries with DO set.
        // For DO=0, first try with DO=0 and then try with DO=1. If
        // DO=1 has an answer, remove DNSSEC related resource records.
        // If AD is clear then clear the AD bit.

        // If DO is set then AD is irrelevant. Force AD to be set for
        // consistency (if DO is set then with respect to the AD flag
        // the behavior is as if AD is set.

        println!("cache_lookup_do_ad: {key:?}");
        if key.dnssec_ok {
            assert!(key.ad);
        }

        let opt_value = self.cache_lookup_ad(key).await;
        if opt_value.is_some() || key.dnssec_ok {
            return opt_value;
        }

        if key.qclass == Class::In && is_dnssec(key.qtype) {
            // An explicit request for one of the DNSSEC type but
            // DO is not set. Force the request to be sent explicitly.
            return None;
        }

        let mut alt_key = key.clone();
        alt_key.dnssec_ok = true;
        alt_key.ad = true;
        println!("cache_lookup_do_ad: alt {alt_key:?}");
        let opt_value = self.cache.get(&alt_key).await;
        println!("cache_lookup_do_ad: cached alt value {opt_value:?}");
        if let Some(value) = &opt_value {
            match &value.response {
                Err(_) => {
                    // Just insert the error
                    self.cache_insert(key.clone(), value.clone()).await;
                }
                Ok(msg) => {
                    let msg = remove_dnssec(msg, key.ad);
                    let value =
                        Arc::new(Value::<T>::new_from_value_and_response(
                            value.clone(),
                            Ok(msg),
                        ));
                    self.cache_insert(key.clone(), value.clone()).await;
                    return Some(value);
                }
            }
        }
        opt_value
    }

    async fn cache_lookup_ad(&self, key: &Key) -> Option<Arc<Value<T>>> {
        // For AD=1 we can only use responses to queries with AD set.
        // For AD=0, first try with AD=0 and then try with AD=1. If
        // AD=1 has an answer, clear the AD bit.
        println!("cache_lookup_ad: {key:?}");
        let opt_value = self.cache.get(key).await;
        println!("cache_lookup_ad: get cached value {opt_value:?}");
        if opt_value.is_some() || key.ad {
            return opt_value;
        }
        let mut alt_key = key.clone();
        alt_key.ad = true;
        println!("cache_lookup_ad: alt {alt_key:?}");
        let opt_value = self.cache.get(&alt_key).await;
        println!("cache_lookup_ad: get alt cached value {opt_value:?}");
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
                        return Some(value.clone());
                    }

                    let msg = clear_ad(msg);
                    let value =
                        Arc::new(Value::<T>::new_from_value_and_response(
                            value.clone(),
                            Ok(msg),
                        ));
                    self.cache_insert(key.clone(), value.clone()).await;
                    return Some(value);
                }
            }
        }
        opt_value
    }

    async fn cache_insert(&self, key: Key, value: Arc<Value<T>>) {
        if value.validity.is_zero() {
            // Do not insert cache value that are valid for zero duration.
            return;
        }
        let value = match &value.response {
            Err(_) => {
                // Just insert the error
                value
            }
            Ok(msg) => {
                if msg.header().aa() {
                    let msg = clear_aa(msg);
                    Arc::new(Value::<T>::new_from_value_and_response(
                        value.clone(),
                        Ok(msg),
                    ))
                } else {
                    // AA is clear. Just insert this value.
                    value
                }
            }
        };

        println!("cache_insert: inserting response {key:?} {value:?}");
        self.cache.insert(key, value).await
    }
}

impl<CR, Upstream, T> Debug for Request<CR, Upstream, T>
where
    CR: Send + Sync,
    Upstream: Send + Sync,
    T: Send + Sync + Time,
{
    fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        todo!()
    }
}

impl<CR, Upstream, T> GetResponse for Request<CR, Upstream, T>
where
    CR: Clone + ComposeRequest + Debug + Sync,
    Upstream: SendRequest<CR> + Send + Sync + 'static,
    T: Debug + Time + Send + Sync + 'static,
{
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ Key ------------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Key {
    qname: Dname<Vec<u8>>,
    qclass: Class,
    qtype: Rtype,
    ad: bool,
    cd: bool,
    dnssec_ok: bool,
    rd: bool,
}

impl Key {
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
        let mut qname = qname.to_dname().unwrap();

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
struct Value<T>
where
    T: Send + Sync + Time,
{
    creation: T::Instant,
    validity: Duration,
    response: Result<Message<Bytes>, Error>,
}

impl<T> Value<T>
where
    T: Send + Sync + Time,
{
    fn new(response: &Result<Message<Bytes>, Error>) -> Value<T> {
        Self {
            creation: T::now(),
            validity: validity(response),
            response: response.clone(),
        }
    }
    fn new_from_value_and_response(
        val: Arc<Value<T>>,
        response: Result<Message<Bytes>, Error>,
    ) -> Value<T> {
        Self {
            creation: val.creation,
            validity: validity(&response),
            response,
        }
    }
}

//------------ Utility functions ----------------------------------------------

fn handle_cache_value<TDN, T>(
    orig_qname: TDN,
    value: Arc<Value<T>>,
) -> Option<Result<Message<Bytes>, Error>>
where
    TDN: ToDname + Clone,
    T: Send + Sync + Time,
{
    let elapsed = value.creation.elapsed();
    println!("handle_cache_value: elapsed {elapsed:?}");
    if elapsed > value.validity {
        return None;
    }
    let secs = elapsed.as_secs() as u32;
    let response = decrement_ttl(orig_qname, &value.response, secs);
    Some(response)
}

fn validity(response: &Result<Message<Bytes>, Error>) -> Duration {
    let msg = match response {
        Err(_) => return DEF_TRANSPORT_FAILURE_DURATION,
        Ok(msg) => msg,
    };

    let mut min_val = MAX_VALIDITY;

    match get_opt_rcode(msg) {
        OptRcode::NoError => {
            match classify_no_error(msg) {
                NoErrorType::Answer => (),
                NoErrorType::NoData => min_val = min(min_val, DEF_NODATA_TTL),
                NoErrorType::Delegation => {
                    min_val = min(min_val, DEF_DELEGATION_TTL)
                }
                NoErrorType::NoErrorWeird =>
                // Weird NODATA response. Don't cache this.
                {
                    min_val = 0
                }
            }
        }
        OptRcode::NXDomain => {
            min_val = min(min_val, DEF_NXDOMAIN_TTL);
        }

        _ => {
            min_val = min(min_val, DEF_MISC_ERROR_TTL);
        }
    }

    let msg = msg.question();
    let mut msg = msg.answer().unwrap();
    for rr in &mut msg {
        let rr = rr.unwrap();
        min_val = min(min_val, rr.ttl().as_secs());
    }

    let mut msg = msg
        .next_section()
        .unwrap()
        .expect("section should be present");
    for rr in &mut msg {
        let rr = rr.unwrap();
        min_val = min(min_val, rr.ttl().as_secs());
    }

    let msg = msg
        .next_section()
        .unwrap()
        .expect("section should be present");
    for rr in msg {
        let rr = rr.unwrap();
        if rr.rtype() != Rtype::Opt {
            min_val = min(min_val, rr.ttl().as_secs());
        }
    }

    Duration::from_secs(min_val.into())
}

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
        let rr = rr.unwrap();
        target
            .push((orig_qname.clone(), rr.qtype(), rr.qclass()))
            .unwrap();
    }
    let mut source = source.answer().unwrap();
    let mut target = target.answer();
    for rr in &mut source {
        let mut rr = rr
            .unwrap()
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .expect("record expected");
        rr.set_ttl(rr.ttl() - amount);
        target.push(rr).unwrap();
    }

    let mut source = source
        .next_section()
        .unwrap()
        .expect("section should be present");
    let mut target = target.authority();
    for rr in &mut source {
        let mut rr = rr
            .unwrap()
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .expect("record expected");
        rr.set_ttl(rr.ttl() - amount);
        target.push(rr).unwrap();
    }

    let source = source
        .next_section()
        .unwrap()
        .expect("section should be present");
    let mut target = target.additional();
    for rr in source {
        let rr = rr.unwrap();
        let mut rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .expect("record expected");
        if rr.rtype() != Rtype::Opt {
            rr.set_ttl(rr.ttl() - amount);
        }
        target.push(rr).unwrap();
    }

    let result = target.as_builder().clone();
    let msg =
        Message::<Bytes>::from_octets(result.finish().into_target().into())
            .expect(
                "Message should be able to parse output from MessageBuilder",
            );
    Ok(msg)
}

fn remove_dnssec(msg: &Message<Bytes>, ad: bool) -> Message<Bytes> {
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
        target.push(rr.unwrap()).unwrap();
    }
    let mut source = source.answer().unwrap();
    let mut target = target.answer();
    for rr in &mut source {
        let rr = rr
            .unwrap()
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .expect("record expected");
        if is_dnssec(rr.rtype()) {
            continue;
        }
        target.push(rr).unwrap();
    }

    let mut source = source
        .next_section()
        .unwrap()
        .expect("section should be present");
    let mut target = target.authority();
    for rr in &mut source {
        let rr = rr
            .unwrap()
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .expect("record expected");
        if is_dnssec(rr.rtype()) {
            continue;
        }
        target.push(rr).unwrap();
    }

    let source = source
        .next_section()
        .unwrap()
        .expect("section should be present");
    let mut target = target.additional();
    for rr in source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .expect("record expected");
        if is_dnssec(rr.rtype()) {
            continue;
        }
        target.push(rr).unwrap();
    }

    let result = target.as_builder().clone();
    Message::<Bytes>::from_octets(result.finish().into_target().into())
        .expect("Message should be able to parse output from MessageBuilder")
}

fn is_dnssec(rtype: Rtype) -> bool {
    rtype == Rtype::Rrsig || rtype == Rtype::Nsec || rtype == Rtype::Nsec3
}

enum NoErrorType {
    Answer,
    NoData,
    Delegation,
    NoErrorWeird,
}

fn classify_no_error<Octs>(msg: &Message<Octs>) -> NoErrorType
where
    Octs: Octets,
{
    // Check if we have something that resembles an answer.
    let mut question_section = msg.question();
    let question = question_section.next().unwrap().unwrap();
    let qtype = question.qtype();
    let qclass = question.qclass();

    // Note we only look qtype and qclass. The goal is not to perform
    // a consistency check. Just whether there is supposed to be an
    // answer or not.
    let mut msg = msg.answer().unwrap();
    for rr in &mut msg {
        let rr = rr.unwrap();
        if rr.rtype() == qtype && rr.class() == qclass {
            // We found an answer.
            return NoErrorType::Answer;
        }
    }

    // No answer. Check the authority section for SOA and NS records.
    // If the SOA is present then the response is a NODATA response.
    // If SOA records are absent but NS records are present then the
    // response is a delegation.
    let mut found_ns = false;
    let mut msg = msg
        .next_section()
        .unwrap()
        .expect("section should be present");
    for rr in &mut msg {
        let rr = rr.unwrap();
        if rr.class() == qclass && rr.rtype() == Rtype::Soa {
            return NoErrorType::NoData;
        }
        if rr.class() == qclass && rr.rtype() == Rtype::Ns {
            found_ns = true;
        }
    }

    if found_ns {
        return NoErrorType::Delegation;
    }

    // Neither SOA nor NS were found. This is a broken response.
    NoErrorType::NoErrorWeird
}

/// Get the extended rcode of a message.
fn get_opt_rcode<Octs: Octets>(msg: &Message<Octs>) -> OptRcode {
    let opt = msg.opt();
    match opt {
        Some(opt) => opt.rcode(msg.header()),
        None => {
            // Convert Rcode to OptRcode, this should be part of
            // OptRcode
            OptRcode::from_int(msg.header().rcode().to_int() as u16)
        }
    }
}

fn clear_aa(msg: &Message<Bytes>) -> Message<Bytes> {
    // Assume the clear_aa will be called only if AA is set. So no need to
    // optimize for the case where AA is clear.
    let mut msg =
        Message::<Vec<u8>>::from_octets(msg.as_slice().into()).unwrap();
    let hdr = msg.header_mut();
    hdr.set_aa(false);
    Message::<Bytes>::from_octets(msg.into_octets().into()).unwrap()
}

fn clear_ad(msg: &Message<Bytes>) -> Message<Bytes> {
    // Assume the clear_ad will be called only if AD is set. So no need to
    // optimize for the case where AD is clear.
    let mut msg =
        Message::<Vec<u8>>::from_octets(msg.as_slice().into()).unwrap();
    let hdr = msg.header_mut();
    hdr.set_ad(false);
    Message::<Bytes>::from_octets(msg.into_octets().into()).unwrap()
}

fn clear_rd(msg: &Message<Bytes>) -> Message<Bytes> {
    // Assume the clear_rd will be called only if RD is set. So no need to
    // optimize for the case where RD is clear.
    let mut msg =
        Message::<Vec<u8>>::from_octets(msg.as_slice().into()).unwrap();
    let hdr = msg.header_mut();
    hdr.set_rd(false);
    Message::<Bytes>::from_octets(msg.into_octets().into()).unwrap()
}
