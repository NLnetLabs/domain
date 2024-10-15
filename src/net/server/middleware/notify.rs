//! RFC 1996 DNS NOTIFY related message processing.
//!
//! Quoting [RFC 1996], DNS NOTIFY is the mechanism _"by which a master server
//! advises a set of slave servers that the master's data has been changed and
//! that a query should be initiated to discover the new data."_
//!
//! The middleware service requires an implementation of the [`Notifiable`]
//! trait to which it forwards received notifications, referred to as the
//! notify target from here on.
//!
//! The middleware service is intended to be used by "slave" implementations
//! and provides a thin layer around receiving and responding to DNS NOTIFY
//! messages, extracting the key data and making it available to the notify
//! target.
//!
//! No actual handling of the received data is done by this module. In
//! particular the following parts of RFC 1996 are NOT implemented:
//!
//! - Messages with non-zero values in fields not described by RFC 1996 are
//!   NOT ignored by this middleware. (RFC 1996 section 3.2)
//!
//! - This module does NOT _"query its masters"_ or initiate XFR transfers.
//!   (RFC 1996 section 3.11)
//!
//! - Any "unsecure hint" contained in the answer section is ignored by this
//!   middleware and is NOT passed to the notify target. (RFC 1996 section
//!   3.7)
//!
//! - NOTIFY requests received from unknown masters are NOT ignored or logged
//!   as this middleware has no knowledge of the known masters. (RFC 1996
//!   section 3.10)
//!
//! - No defering of _"action on any subsequent NOTIFY with the same <QNAME,
//!   QCLASS, QTYPE> until it has completed the transcation begun by the first
//!   NOTIFY"_ is done by this middleware, as it has no knowledge of whether
//!   the notify target begins or completes a transaction. (RFC 1996 section
//!   4.4)
//!
//! - Only QTYPE SOA is supported. NOTIFY messages with other QTYPEs will be
//!   propagated unmodified to the next middleware or application service in
//!   the layered stack of services.
//!
//! [RFC 1996]: https://www.rfc-editor.org/info/rfc1996

use core::future::{ready, Future, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;
use core::pin::Pin;

use std::boxed::Box;
use std::fmt::Debug;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream::{once, Once, Stream};
use octseq::Octets;
use tracing::{error, info, warn};

use crate::base::iana::{Class, Opcode, OptRcode, Rcode};
use crate::base::message::CopyRecordsError;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::name::Name;
use crate::base::net::IpAddr;
use crate::base::wire::Composer;
use crate::base::{
    Message, ParsedName, Question, Rtype, StreamTarget, ToName,
};
use crate::net::server::message::Request;
use crate::net::server::middleware::stream::MiddlewareStream;
use crate::net::server::service::{CallResult, Service};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::AllRecordData;

/// A DNS NOTIFY middleware service.
///
/// [NotifyMiddlewareSvc] implements an [RFC 1996] compliant recipient of DNS
/// NOTIFY messages.
///
/// See the [module documentation][super] for more information.
///
/// [RFC 1996]: https://www.rfc-editor.org/info/rfc1996
#[derive(Clone, Debug)]
pub struct NotifyMiddlewareSvc<RequestOctets, NextSvc, RequestMeta, N> {
    /// The upstream [`Service`] to pass requests to and receive responses
    /// from.
    next_svc: NextSvc,

    /// The target to send notifications to.
    notify_target: N,

    _phantom: PhantomData<(RequestOctets, RequestMeta)>,
}

impl<RequestOctets, NextSvc, RequestMeta, N>
    NotifyMiddlewareSvc<RequestOctets, NextSvc, RequestMeta, N>
{
    /// Creates an instance of this middleware service.
    ///
    /// The given notify target must implement the [`Notifiable`] trait in
    /// order to actually use this middleware with the target.
    #[must_use]
    pub fn new(next_svc: NextSvc, notify_target: N) -> Self {
        Self {
            next_svc,
            notify_target,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, NextSvc, RequestMeta, N>
    NotifyMiddlewareSvc<RequestOctets, NextSvc, RequestMeta, N>
where
    RequestOctets: Octets + Send + Sync,
    RequestMeta: Clone + Default,
    NextSvc: Service<RequestOctets, RequestMeta>,
    NextSvc::Target: Composer + Default,
    N: Clone + Notifiable + Sync + Send,
{
    /// Pre-process received DNS NOTIFY queries.
    ///
    /// Other types of query will be propagated unmodified to the next
    /// middleware or application service in the layered stack of services.
    async fn preprocess(
        req: &Request<RequestOctets, RequestMeta>,
        notify_target: N,
    ) -> ControlFlow<Once<Ready<<NextSvc::Stream as Stream>::Item>>> {
        let msg = req.message();

        let Some(q) = Self::get_relevant_question(msg) else {
            return ControlFlow::Continue(());
        };

        let class = q.qclass();
        let apex_name = q.qname().to_name();
        let source = req.client_addr().ip();

        // https://datatracker.ietf.org/doc/html/rfc1996#section-3
        //   "3.1. When a master has updated one or more RRs in which slave
        //    servers may be interested, the master may send the changed RR's
        //    name, class, type, and optionally, new RDATA(s), to each known
        //    slave server using a best efforts protocol based on the NOTIFY
        //    opcode."
        //
        // So, we have received a notification from a server that an RR
        // changed that we may be interested in.
        info!(
            "NOTIFY received from {} for zone '{}'",
            req.client_addr(),
            q.qname()
        );

        // https://datatracker.ietf.org/doc/html/rfc1996#section-3
        //   "3.7. A NOTIFY request has QDCOUNT>0, ANCOUNT>=0, AUCOUNT>=0,
        //    ADCOUNT>=0.  If ANCOUNT>0, then the answer section represents an
        //    unsecure hint at the new RRset for this <QNAME,QCLASS,QTYPE>.  A
        //    slave receiving such a hint is free to treat equivilence of this
        //    answer section with its local data as a "no further work needs
        //    to be done" indication.  If ANCOUNT=0, or ANCOUNT>0 and the
        //    answer section differs from the slave's local data, then the
        //    slave should query its known masters to retrieve the new data."
        //
        // Note: At the time of writing any answers present in the request are
        // ignored and thus we do not examine the equivalence or otherwise
        // compared to local data.

        // https://datatracker.ietf.org/doc/html/rfc1996
        //   "3.10. If a slave receives a NOTIFY request from a host that is
        //   not a known master for the zone containing the QNAME, it should
        //   ignore the request and produce an error message in its operations
        //    log."
        //
        //   "Note: This implies that slaves of a multihomed master must
        //       either know their master by the "closest" of the master's
        //       interface addresses, or must know all of the master's
        //       interface addresses. Otherwise, a valid NOTIFY request might
        //       come from an address that is not on the slave's state list of
        //       masters for the zone, which would be an error."
        //
        // Announce this notification for processing.
        match notify_target
            .notify_zone_changed(class, &apex_name, source)
            .await
        {
            Err(NotifyError::NotAuthForZone) => {
                warn!("Ignoring NOTIFY from {} for zone '{}': Not authoritative for zone",
                    req.client_addr(),
                    q.qname()
                );
                ControlFlow::Break(once(ready(Ok(CallResult::new(
                    mk_error_response(msg, OptRcode::NOTAUTH),
                )))))
            }

            Err(NotifyError::Other) => {
                error!(
                    "Error while processing NOTIFY from {} for zone '{}'.",
                    req.client_addr(),
                    q.qname()
                );
                ControlFlow::Break(once(ready(Ok(CallResult::new(
                    mk_error_response(msg, OptRcode::SERVFAIL),
                )))))
            }

            Ok(()) => {
                // https://datatracker.ietf.org/doc/html/rfc1996#section-4
                //   "4.7 Slave Receives a NOTIFY Request from a Master
                //
                //    When a slave server receives a NOTIFY request from one
                //    of its locally designated masters for the zone enclosing
                //    the given QNAME, with QTYPE=SOA and QR=0, it should
                //    enter the state it would if the zone's refresh timer had
                //    expired.  It will also send a NOTIFY response back to
                //    the NOTIFY request's source, with the following
                //    characteristics:
                //
                //       query ID:   (same)
                //       op:         NOTIFY (4)
                //       resp:       NOERROR
                //       flags:      QR AA
                //       qcount:     1
                //       qname:      (zone name)
                //       qclass:     (zone class)
                //       qtype:      T_SOA
                //
                //    This is intended to be identical to the NOTIFY request,
                //    except that the QR bit is also set.  The query ID of the
                //    response must be the same as was received in the
                //    request."
                let mut additional = Self::copy_message(msg).unwrap();

                let response_hdr = additional.header_mut();
                response_hdr.set_opcode(Opcode::NOTIFY);
                response_hdr.set_rcode(Rcode::NOERROR);
                response_hdr.set_qr(true);
                response_hdr.set_aa(true);

                let res = once(ready(Ok(CallResult::new(additional))));
                ControlFlow::Break(res)
            }
        }
    }

    /// Is this message for us?
    ///
    /// Returns `Some(Question)` if the given query uses OPCODE NOTIFY and has
    /// a first question with a QTYPE of `SOA`, `None` otherwise.
    fn get_relevant_question(
        msg: &Message<RequestOctets>,
    ) -> Option<Question<ParsedName<RequestOctets::Range<'_>>>> {
        // NOTE: If this middleware is used with a server that primarily
        // receives Opcode::QUERY it would be more efficient to place a
        // "router" middleware in front of this middleware that routes
        // requests by Opcode to separate dedicated middleware "chains".
        if Opcode::NOTIFY == msg.header().opcode() {
            if let Some(q) = msg.first_question() {
                if q.qtype() == Rtype::SOA {
                    return Some(q);
                }
            }
        }

        None
    }

    /// Create a copy of the given message.
    ///
    /// The copy will be returned as an [`AdditionalBuilder`] so that the
    /// caller can further modify it before using it.
    /// `
    // Based on RequestMessage::append_message_impl().
    fn copy_message(
        source: &Message<RequestOctets>,
    ) -> Result<
        AdditionalBuilder<StreamTarget<NextSvc::Target>>,
        CopyRecordsError,
    > {
        let mut builder = mk_builder_for_target();
        *builder.header_mut() = source.header();

        let source = source.question();
        let mut question = builder.question();
        for rr in source {
            question.push(rr?)?;
        }
        let mut source = source.answer()?;
        let mut answer = question.answer();
        for rr in &mut source {
            let rr = rr?
                .into_record::<AllRecordData<_, ParsedName<_>>>()?
                .expect("record expected");
            answer.push(rr)?;
        }

        let mut source =
            source.next_section()?.expect("section should be present");
        let mut authority = answer.authority();
        for rr in &mut source {
            let rr = rr?
                .into_record::<AllRecordData<_, ParsedName<_>>>()?
                .expect("record expected");
            authority.push(rr)?;
        }

        let source =
            source.next_section()?.expect("section should be present");
        let mut additional = authority.additional();
        for rr in source {
            let rr = rr?;
            if rr.rtype() != Rtype::OPT {
                let rr = rr
                    .into_record::<AllRecordData<_, ParsedName<_>>>()?
                    .expect("record expected");
                additional.push(rr)?;
            }
        }

        Ok(additional)
    }
}

//--- Service

impl<RequestOctets, NextSvc, RequestMeta, N>
    Service<RequestOctets, RequestMeta>
    for NotifyMiddlewareSvc<RequestOctets, NextSvc, RequestMeta, N>
where
    RequestOctets: Octets + Send + Sync + 'static,
    RequestMeta: Clone + Default + Sync + Send + 'static,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, RequestMeta>
        + Clone
        + 'static
        + Send
        + Sync
        + Unpin,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    N: Notifiable + Clone + Sync + Send + 'static,
{
    type Target = NextSvc::Target;
    type Stream = MiddlewareStream<
        NextSvc::Future,
        NextSvc::Stream,
        NextSvc::Stream,
        Once<Ready<<NextSvc::Stream as Stream>::Item>>,
        <NextSvc::Stream as Stream>::Item,
    >;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send + Sync>>;

    fn call(
        &self,
        request: Request<RequestOctets, RequestMeta>,
    ) -> Self::Future {
        let request = request.clone();
        let next_svc = self.next_svc.clone();
        let notify_target = self.notify_target.clone();
        Box::pin(async move {
            match Self::preprocess(&request, notify_target).await {
                ControlFlow::Continue(()) => {
                    let stream = next_svc.call(request).await;
                    MiddlewareStream::IdentityStream(stream)
                }
                ControlFlow::Break(stream) => {
                    MiddlewareStream::Result(stream)
                }
            }
        })
    }
}

//------------ NotifyError ----------------------------------------------------

/// Errors reportable by a [`Notifiable`] trait impl.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotifyError {
    /// We are not authoritative for the zone.
    NotAuthForZone,

    /// Notify handling failed for some other reason.
    Other,
}

//------------ Notifiable -----------------------------------------------------

/// A target for notifications sent by [`NotifyMiddlewareSvc`].
// Note: The fn signatures can be simplified to fn() -> impl Future<...> if
// our MSRV is later increased.
pub trait Notifiable {
    /// A notification that the content of a zone has changed.
    ///
    /// The origin of the notification is the passed `source` IP address.
    fn notify_zone_changed(
        &self,
        class: Class,
        apex_name: &Name<Bytes>,
        source: IpAddr,
    ) -> Pin<
        Box<dyn Future<Output = Result<(), NotifyError>> + Sync + Send + '_>,
    >;
}

//--- impl for Arc

impl<T: Notifiable> Notifiable for Arc<T> {
    fn notify_zone_changed(
        &self,
        class: Class,
        apex_name: &Name<Bytes>,
        source: IpAddr,
    ) -> Pin<
        Box<dyn Future<Output = Result<(), NotifyError>> + Sync + Send + '_>,
    > {
        (**self).notify_zone_changed(class, apex_name, source)
    }
}
