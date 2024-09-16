//! A DNSSEC validator.
//!
//! This module implements a DNSSEC validator provided as a pass through
//! transport. It implements that parts of
//! [RFC 4035](https://www.rfc-editor.org/info/rfc4035) related to converting
//! a validation status to a result code (server failure) and setting or
//! clearing the AD flag.
//! For details of the validator see the
//! [validator](crate::validator) module.
//!
//! # Upstream transports
//!
//! When it comes to the upstream transport, this module is similar to
//! other client transport modules in that it takes a transport that
//! implements the [SendRequest] trait. However, the validator transport
//! needs a [ValidationContext] which in turn also needs a client transport.
//! The ValidationContext needs to generate DS and DNSKEY request and for
//! it needs a client transport that allows the creation of new DNS
//! request. Therefore the ValidationContext requires client tranport that
//! provides `SendRequest<RequestMessage<Octs>>`. It is often convenient
//! to use a single upstream client transport for both the validator transport
//! and the ValidationContext. However, it is quite possible to use
//! different transports.
//!
//! # Caching
//!
//! Ideally caching should be done before (downstream of) the validator
//! transport. This way validated results are cached. A cache that is
//! upstream of the validator would avoid network traffic, but would require
//! some amount of validating for each request.
//!
//! The validator has some internal caches (see the
//! [validator](crate::validator) module) so
//! there is no direct need for a cache upstream of the validator. Caching
//! becomes more complex if there is validator that uses the validator.
//! in that case, the downstream validator will likely issues requests for
//! DS and DNSKEY records that the validator issues as well. Because there is
//! no upstream cache, those requests will go over the upstream transport
//! twice. One solution to that is to create a new type of cache that only
//! caches DS and DNSKEY records and insert that upstream of the validator.

//! # Example
//! ```rust,no_run
//! # use domain::base::{MessageBuilder, Name, Rtype};
//! # use domain::net::client::dgram_stream;
//! # use domain::net::client::protocol::{TcpConnect, UdpConnect};
//! # use domain::net::client::request::{RequestMessage, SendRequest};
//! # use domain::net::client::validator;
//! # use domain::validator::anchor::TrustAnchors;
//! # use domain::validator::context::ValidationContext;
//! # use std::net::{IpAddr, SocketAddr};
//! # use std::str::FromStr;
//! # use std::sync::Arc;
//! #
//! # async fn g() {
//! #     let server_addr = SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53);
//! #
//! #     let udp_connect = UdpConnect::new(server_addr);
//! #     let tcp_connect = TcpConnect::new(server_addr);
//! #     let (udptcp_conn, transport) = dgram_stream::Connection::new(udp_connect, tcp_connect);
//! #
//! #     tokio::spawn(async move {
//! #         transport.run().await;
//! #         println!("UDP+TCP run exited");
//! #     });
//! #
//! #     let mut msg = MessageBuilder::new_vec();
//! #     msg.header_mut().set_rd(true);
//! #     msg.header_mut().set_ad(true);
//! #     let mut msg = msg.question();
//! #     msg.push((Name::vec_from_str("example.com").unwrap(), Rtype::AAAA))
//! #         .unwrap();
//!     let req = RequestMessage::new(msg).unwrap();
//!
//!     let ta = TrustAnchors::from_u8(b". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU= ;{id = 20326 (ksk), size = 2048b} ;;state=2 [  VALID  ] ;;count=0 ;;lastchange=1683463064 ;;Sun May  7 12:37:44 2023").unwrap();
//!     let vc = ValidationContext::new(ta, udptcp_conn.clone());
//!
//!     let vac_conn = validator::Connection::new(udptcp_conn, Arc::new(vc));
//!
//!     // Send a query message.
//!     let mut request = vac_conn.send_request(req.clone());
//!
//!     // Get the reply
//!     println!("Wating for validator reply");
//!     let reply = request.get_response().await.unwrap();
//!     println!("Validator reply: {reply:?}");
//! }
//! ```

use crate::base::iana::Rcode;
use crate::base::opt::{AllOptData, ExtendedError};
use crate::base::{
    Message, MessageBuilder, ParsedName, Rtype, StaticCompressor,
};
use crate::dep::octseq::{Octets, OctetsFrom, OctetsInto};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, RequestMessage, SendRequest,
};
use crate::rdata::AllRecordData;
use crate::validator::context::{ValidationContext, ValidationState};
use bytes::Bytes;
use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

//------------ Config ---------------------------------------------------------

/// Configuration of a validator.
#[derive(Clone, Default, Debug)]
pub struct Config {}

impl Config {
    /// Creates a new config with default values.
    ///
    /// The default values are documented at the relevant set_* methods.
    pub fn new() -> Self {
        Default::default()
    }
}

//------------ Connection -----------------------------------------------------

#[derive(Clone)]
/// A connection that DNSSEC validates responses from an upstream connection.
pub struct Connection<Upstream, VCOcts, VCUpstream> {
    /// Upstream transport to use for requests.
    upstream: Upstream,

    /// The validation context for this connection.
    vc: Arc<ValidationContext<VCUpstream>>,

    /// The configuration of this connection.
    config: Config,

    /// Phantom field to capture `VCOcts`.
    _phantom: PhantomData<VCOcts>,
}

impl<Upstream, VCOcts, VCUpstream> Connection<Upstream, VCOcts, VCUpstream> {
    /// Create a new connection with default configuration parameters.
    ///
    /// Note that Upstream needs to implement [SendRequest]
    /// (and Clone/Send/Sync) to be useful.
    pub fn new(
        upstream: Upstream,
        vc: Arc<ValidationContext<VCUpstream>>,
    ) -> Self {
        Self::with_config(upstream, vc, Default::default())
    }

    /// Create a new connection with specified configuration parameters.
    ///
    /// Note that Upstream needs to implement [SendRequest]
    /// (and Clone/Send/Sync) to be useful.
    pub fn with_config(
        upstream: Upstream,
        vc: Arc<ValidationContext<VCUpstream>>,
        config: Config,
    ) -> Self {
        Self {
            upstream,
            vc,
            config,
            _phantom: PhantomData,
        }
    }
}

//------------ SendRequest ----------------------------------------------------

impl<CR, Upstream, VCOcts, VCUpstream> SendRequest<CR>
    for Connection<Upstream, VCOcts, VCUpstream>
where
    CR: ComposeRequest + Clone + 'static,
    Upstream: Clone + SendRequest<CR> + Send + Sync + 'static,
    VCOcts: AsRef<[u8]>
        + Debug
        + Octets
        + OctetsFrom<Vec<u8>>
        + Send
        + Sync
        + 'static,
    VCUpstream:
        Clone + SendRequest<RequestMessage<VCOcts>> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request::new(
            request_msg,
            self.upstream.clone(),
            self.vc.clone(),
            self.config.clone(),
        ))
    }
}

//------------ Request --------------------------------------------------------

/// The state of a request that is executed.
pub struct Request<CR, Upstream, VCOcts, VCUpstream>
where
    Upstream: Send + Sync,
{
    /// State of the request.
    state: RequestState,

    /// The request message.
    request_msg: CR,

    /// The upstream transport of the connection.
    upstream: Upstream,

    /// The validation context.
    vc: Arc<ValidationContext<VCUpstream>>,

    /// The configuration of the connection.
    _config: Config,

    /// valid of the cd flag in the request.
    cd: bool,

    /// value of the dnssec_ok flag in the request.
    dnssec_ok: bool,

    /// Phantom field to capture `VCOcts`.
    _phantom: PhantomData<VCOcts>,
}

impl<CR, Upstream, VCOcts, VCUpstream>
    Request<CR, Upstream, VCOcts, VCUpstream>
where
    Upstream: SendRequest<CR> + Send + Sync,
{
    /// Create a new Request object.
    fn new(
        request_msg: CR,
        upstream: Upstream,
        vc: Arc<ValidationContext<VCUpstream>>,
        config: Config,
    ) -> Request<CR, Upstream, VCOcts, VCUpstream> {
        Self {
            state: RequestState::Init,
            request_msg,
            upstream,
            vc,
            _config: config,
            cd: false,
            dnssec_ok: false,
            _phantom: PhantomData,
        }
    }

    /// This is the implementation of the get_response method.
    async fn get_response_impl<Octs>(
        &mut self,
    ) -> Result<Message<Bytes>, Error>
    where
        CR: Clone + ComposeRequest,
        Upstream: SendRequest<CR>,
        Octs:
            AsRef<[u8]> + Debug + Octets + OctetsFrom<Vec<u8>> + Send + Sync,
        VCUpstream: SendRequest<RequestMessage<Octs>>,
    {
        loop {
            match &mut self.state {
                RequestState::Init => {
                    // Store the DO flag of the request.
                    self.dnssec_ok = self.request_msg.dnssec_ok();
                    if !self.dnssec_ok {
                        // Set the DO flag, otherwise we can't validate.
                        self.request_msg.set_dnssec_ok(true);
                    }

                    // Store the CD flag of the request.
                    self.cd = self.request_msg.header().cd();
                    if !self.cd {
                        // Set the CD flag to get all results even if they
                        // fail to validate upstream.
                        self.request_msg.header_mut().set_cd(true);
                    }

                    let request =
                        self.upstream.send_request(self.request_msg.clone());
                    self.state = RequestState::GetResponse(request);
                    continue;
                }

                RequestState::GetResponse(request) => {
                    let response_msg = request.get_response().await?;

                    if self.cd {
                        if self.dnssec_ok {
                            // Clear the AD flag if it is clear. Check if CD
                            // is set. If either AD is set or CD is clear then
                            // correct the message.
                            if response_msg.header().ad()
                                || !response_msg.header().cd()
                            {
                                let mut response_msg = Message::from_octets(
                                    response_msg.as_slice().to_vec(),
                                )?;
                                response_msg.header_mut().set_ad(false);
                                response_msg.header_mut().set_cd(true);
                                let response_msg =
                                    Message::<Bytes>::from_octets(
                                        response_msg
                                            .into_octets()
                                            .octets_into(),
                                    )?;
                                return Ok(response_msg);
                            }
                            return Ok(response_msg);
                        } else {
                            let msg =
                                remove_dnssec(&response_msg, false, self.cd);
                            return msg;
                        }
                    }

                    self.state = RequestState::Validate(response_msg);
                    continue;
                }

                RequestState::Validate(response_msg) => {
                    let res = self.vc.validate_msg(response_msg).await;
                    return match res {
                        Err(err) => Err(Error::Validation(err)),
                        Ok((state, opt_ede)) => {
                            match state {
                                ValidationState::Secure => {
                                    // Check the state of the DO flag to see
                                    // if we have to strip DNSSEC records. Set
                                    // the AD flag if it is not set and either
                                    // AD or DO is set in the request.
                                    // We always have to clear CD.
                                    if self.dnssec_ok {
                                        // Set AD and clear CD.
                                        let mut response_msg =
                                            Message::from_octets(
                                                response_msg
                                                    .as_slice()
                                                    .to_vec(),
                                            )?;
                                        response_msg
                                            .header_mut()
                                            .set_ad(true);
                                        response_msg
                                            .header_mut()
                                            .set_cd(false);
                                        let response_msg =
                                            Message::<Bytes>::from_octets(
                                                response_msg
                                                    .into_octets()
                                                    .octets_into(),
                                            )?;
                                        Ok(response_msg)
                                    } else {
                                        // Set AD if it was set in the request.
                                        let msg = remove_dnssec(
                                            response_msg,
                                            self.request_msg.header().ad(),
                                            false,
                                        );
                                        msg
                                    }
                                }
                                ValidationState::Bogus => {
                                    serve_fail(response_msg, opt_ede)
                                }
                                ValidationState::Insecure
                                | ValidationState::Indeterminate => {
                                    let response_msg = match opt_ede {
                                        Some(ede) => {
                                            add_opt(response_msg, ede)?
                                        }
                                        None => response_msg.clone(),
                                    };
                                    // Check the state of the DO flag to see
                                    // if we have to strip DNSSEC records.
                                    // Clear the AD flag if it is set. Always
                                    // clear CD.
                                    if self.dnssec_ok {
                                        // Clear AD if it is set. Clear CD.
                                        let mut response_msg =
                                            Message::from_octets(
                                                response_msg
                                                    .as_slice()
                                                    .to_vec(),
                                            )?;
                                        response_msg
                                            .header_mut()
                                            .set_ad(false);
                                        response_msg
                                            .header_mut()
                                            .set_cd(false);
                                        let response_msg =
                                            Message::<Bytes>::from_octets(
                                                response_msg
                                                    .into_octets()
                                                    .octets_into(),
                                            )?;
                                        Ok(response_msg)
                                    } else {
                                        remove_dnssec(
                                            &response_msg,
                                            false,
                                            false,
                                        )
                                    }
                                }
                            }
                        }
                    };
                }
            }
        }
    }
}

impl<CR, Upstream, VCOcts, VCUpstream> Debug
    for Request<CR, Upstream, VCOcts, VCUpstream>
where
    Upstream: Send + Sync,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

impl<CR, Upstream, VCOcts, VCUpstream> GetResponse
    for Request<CR, Upstream, VCOcts, VCUpstream>
where
    CR: Clone + ComposeRequest,
    Upstream: Clone + SendRequest<CR> + Send + Sync,
    VCOcts: AsRef<[u8]> + Debug + Octets + OctetsFrom<Vec<u8>> + Send + Sync,
    VCUpstream: Clone + SendRequest<RequestMessage<VCOcts>> + Send + Sync,
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
    /// Initial state.
    Init,

    /// Wait for a response.
    GetResponse(Box<dyn GetResponse + Send + Sync>),

    /// Wait for validation to complete.
    Validate(Message<Bytes>),
}

/// Return a new message without the DNSSEC type DNSKEY, RRSIG, NSEC, and NSEC3.
/// Only RRSIG needs to be removed
/// from the answer section unless the qtype is RRSIG. Remove all
/// DNSSEC records from the authority and additional sections.
fn remove_dnssec(
    msg: &Message<Bytes>,
    ad: bool,
    cd: bool,
) -> Result<Message<Bytes>, Error> {
    let mut target =
        MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
            .expect("Vec is expected to have enough space");

    let source = msg;
    let opt = source.opt();

    *target.header_mut() = source.header();

    if ad != source.header().ad() {
        // Change AD.
        target.header_mut().set_ad(ad);
    }
    if cd != source.header().cd() {
        // Change CD.
        target.header_mut().set_cd(cd);
    }

    let source = source.question();
    let mut target = target.question();
    let mut qtype = Rtype::ANY;
    for rr in source {
        qtype = rr.clone()?.qtype();
        target.push(rr?).expect("push failed");
    }
    let mut source = source.answer()?;
    let mut target = target.answer();
    for rr in &mut source {
        let rr = rr?
            .into_record::<AllRecordData<_, ParsedName<_>>>()?
            .expect("record expected");
        if is_dnssec(rr.rtype()) && rr.rtype() != qtype {
            continue;
        }
        target.push(rr).expect("push error");
    }

    let mut source =
        source.next_section()?.expect("section should be present");
    let mut target = target.authority();
    for rr in &mut source {
        let rr = rr?
            .into_record::<AllRecordData<_, ParsedName<_>>>()?
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
            .into_record::<AllRecordData<_, ParsedName<_>>>()?
            .expect("record expected");
        if rr.rtype() == Rtype::OPT {
            continue;
        }
        if is_dnssec(rr.rtype()) {
            continue;
        }
        target.push(rr).expect("push error");
    }
    if let Some(opt) = opt {
        target
            .opt(|ob| {
                ob.set_dnssec_ok(false);
                // XXX something is missing ob.set_rcode(opt.rcode());
                ob.set_udp_payload_size(opt.udp_payload_size());
                ob.set_version(opt.version());
                for o in opt.opt().iter() {
                    let x: AllOptData<_, _> = o.expect("should not fail");
                    ob.push(&x)?;
                }
                Ok(())
            })
            .expect("should not fail");
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
    rtype == Rtype::DNSKEY
        || rtype == Rtype::RRSIG
        || rtype == Rtype::NSEC
        || rtype == Rtype::NSEC3
}

/// Return a new message that adds an `ExtendedError` option to an existing
/// message.
fn add_opt(
    msg: &Message<Bytes>,
    ede: ExtendedError<Vec<u8>>,
) -> Result<Message<Bytes>, Error> {
    let mut target =
        MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
            .expect("Vec is expected to have enough space");

    let source = msg;

    *target.header_mut() = msg.header();

    let source = source.question();
    let mut target = target.question();
    for rr in source {
        target.push(rr?).expect("should not fail");
    }
    let mut source = source.answer()?;
    let mut target = target.answer();
    for rr in &mut source {
        let rr = rr?
            .into_record::<AllRecordData<_, ParsedName<_>>>()?
            .expect("record expected");
        target.push(rr).expect("should not fail");
    }

    let mut source =
        source.next_section()?.expect("section should be present");
    let mut target = target.authority();
    for rr in &mut source {
        let rr = rr?
            .into_record::<AllRecordData<_, ParsedName<_>>>()?
            .expect("record expected");
        target.push(rr).expect("should not fail");
    }

    let source = source.next_section()?.expect("section should be present");
    let mut target = target.additional();
    for rr in source {
        let rr = rr?;
        if rr.rtype() != Rtype::OPT {
            let rr = rr
                .into_record::<AllRecordData<_, ParsedName<_>>>()?
                .expect("record expected");
            target.push(rr).expect("should not fail");
        }
    }

    if let Some(opt) = msg.opt() {
        target
            .opt(|ob| {
                ob.set_dnssec_ok(opt.dnssec_ok());
                // XXX something is missing ob.set_rcode(opt.rcode());
                ob.set_udp_payload_size(opt.udp_payload_size());
                ob.set_version(opt.version());
                for o in opt.opt().iter() {
                    let x: AllOptData<_, _> = o.expect("should not fail");
                    ob.push(&x).expect("should not fail");
                }
                ob.push(&ede).expect("should not fail");
                Ok(())
            })
            .expect("should not fail");
    }

    let result = target.as_builder().clone();
    let msg = Message::<Bytes>::from_octets(
        result.finish().into_target().octets_into(),
    )
    .expect("Message should be able to parse output from MessageBuilder");
    Ok(msg)
}

/// Generate a SERVFAIL reply message.
fn serve_fail(
    msg: &Message<Bytes>,
    opt_ede: Option<ExtendedError<Vec<u8>>>,
) -> Result<Message<Bytes>, Error> {
    let mut target =
        MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
            .expect("Vec is expected to have enough space");

    let source = msg;

    *target.header_mut() = msg.header();
    target.header_mut().set_rcode(Rcode::SERVFAIL);
    target.header_mut().set_ad(false);

    let source = source.question();
    let mut target = target.question();
    for rr in source {
        target.push(rr?).expect("should not fail");
    }
    let mut target = target.additional();

    if let Some(opt) = msg.opt() {
        target
            .opt(|ob| {
                ob.set_dnssec_ok(opt.dnssec_ok());
                // XXX something is missing ob.set_rcode(opt.rcode());
                ob.set_udp_payload_size(opt.udp_payload_size());
                ob.set_version(opt.version());
                for o in opt.opt().iter() {
                    let x: AllOptData<_, _> = o.expect("should not fail");
                    ob.push(&x).expect("should not fail");
                }
                if let Some(ede) = opt_ede {
                    ob.push(&ede).expect("should not fail");
                }
                Ok(())
            })
            .expect("should not fail");
    }

    let result = target.as_builder().clone();
    let msg = Message::<Bytes>::from_octets(
        result.finish().into_target().octets_into(),
    )
    .expect("Message should be able to parse output from MessageBuilder");
    Ok(msg)
}
