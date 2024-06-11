//! DNS NOTIFY related message processing.
use core::future::{ready, Future, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;
use core::pin::Pin;

use std::boxed::Box;
use std::sync::Arc;

use futures::stream::{once, Once, Stream};
use octseq::Octets;

use crate::base::iana::{Opcode, OptRcode, Rcode};
use crate::base::message::CopyRecordsError;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{
    Message, ParsedName, Question, Rtype, StreamTarget, ToName,
};
use crate::net::server::message::Request;
use crate::net::server::middleware::stream::MiddlewareStream;
use crate::net::server::service::{CallResult, Service};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::AllRecordData;
use crate::zonecatalog::catalog::{Catalog, CatalogError};
use tracing::{debug, error, info, warn};

/// A DNS NOTIFY middleware service
///
/// Standards covered by ths implementation:
///
/// | RFC    | Status  |
/// |--------|---------|
/// | [1996] | TBD     |
///
/// [1996]: https://datatracker.ietf.org/doc/html/rfc1996
#[derive(Clone, Debug)]
pub struct NotifyMiddlewareSvc<RequestOctets, Svc> {
    svc: Svc,

    catalog: Arc<Catalog>,

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, Svc> NotifyMiddlewareSvc<RequestOctets, Svc> {
    /// Creates an instance of this processor.
    #[must_use]
    pub fn new(svc: Svc, catalog: Arc<Catalog>) -> Self {
        Self {
            svc,
            catalog,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, Svc> NotifyMiddlewareSvc<RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync + Unpin,
    Svc: Service<RequestOctets>,
    Svc::Target: Composer + Default,
{
    async fn preprocess(
        req: &Request<RequestOctets>,
        catalog: Arc<Catalog>,
    ) -> ControlFlow<Once<Ready<<Svc::Stream as Stream>::Item>>> {
        let msg = req.message();

        let Some(q) = Self::get_relevant_question(msg) else {
            return ControlFlow::Continue(());
        };

        let class = q.qclass();
        let apex_name = q.qname().to_name();
        let source = req.client_addr().ip();

        // https://datatracker.ietf.org/doc/html/rfc1996
        //   "3.3. NOTIFY is similar to QUERY in that it has a request message
        //    with the header QR flag "clear" and a response message with QR
        //    "set".  The response message contains no useful information, but
        //    its reception by the master is an indication that the slave has
        //    received the NOTIFY and that the master can remove the slave
        //    from any retry queue for this NOTIFY event."
        match msg.header().qr() {
            false => {
                // https://datatracker.ietf.org/doc/html/rfc1996#section-3
                //   "3.1. When a master has updated one or more RRs in which
                //    slave servers may be interested, the master may send the
                //    changed RR's name, class, type, and optionally, new
                //    RDATA(s), to each known slave server using a best
                //    efforts protocol based on the NOTIFY opcode."
                //
                // So, we have received a notification from a server that an RR
                // changed that we may be interested in.
                info!(
                    "NOTIFY received from {} for zone '{}'",
                    req.client_addr(),
                    q.qname()
                );

                // https://datatracker.ietf.org/doc/html/rfc1996#section-3
                //   "3.7. A NOTIFY request has QDCOUNT>0, ANCOUNT>=0,
                //    AUCOUNT>=0, ADCOUNT>=0.  If ANCOUNT>0, then the answer
                //    section represents an unsecure hint at the new RRset for
                //    this <QNAME,QCLASS,QTYPE>.  A slave receiving such a
                //    hint is free to treat equivilence of this answer section
                //    with its local data as a "no further work needs to be
                //    done" indication.  If ANCOUNT=0, or ANCOUNT>0 and the
                //    answer section differs from the slave's local data, then
                //    the slave should query its known masters to retrieve the
                //    new data."
                //
                // Note: At the time of writing any answers present in the
                // request are ignored and thus we do not examine the
                // equivalence or otherwise compared to local data.

                // https://datatracker.ietf.org/doc/html/rfc1996 "3.10. If a
                //   slave receives a NOTIFY request from a host that is not a
                //   known master for the zone containing the QNAME, it should
                //    ignore the request and produce an error message in its
                //    operations log."
                //
                //   "Note: This implies that slaves of a multihomed master
                //       must either know their master by the "closest" of the
                //       master's interface addresses, or must know all of the
                //       master's interface addresses. Otherwise, a valid
                //       NOTIFY request might come from an address that is not
                //       on the slave's state list of masters for the zone,
                //       which would be an error."
                //
                // We pass the source to the Catalog to compare against the
                // set of known masters for the zone.
                if let Err(err) = catalog
                    .notify_zone_changed(class, &apex_name, source)
                    .await
                {
                    match err {
                        CatalogError::UnknownZone => {
                            warn!("Ignoring NOTIFY from {} for zone '{}': Zone not managed by the catalog",
                                req.client_addr(),
                                q.qname()
                            );
                            return ControlFlow::Break(
                                Self::to_stream_compatible(
                                    mk_error_response(msg, OptRcode::NOTAUTH),
                                ),
                            );
                        }
                        CatalogError::RequestError(_) => {
                            debug!("Ignoring NOTIFY from {} for zone '{}': {err}",
                                req.client_addr(),
                                q.qname()
                            );
                            return ControlFlow::Break(
                                Self::to_stream_compatible(
                                    mk_error_response(msg, OptRcode::FORMERR),
                                ),
                            );
                        }
                        CatalogError::NotRunning
                        | CatalogError::InternalError
                        | CatalogError::ResponseError(_)
                        | CatalogError::IoError(_) => {
                            error!("Error while processing NOTIFY from {} for zone '{}': {err}",
                            req.client_addr(),
                            q.qname()
                            );
                            return ControlFlow::Break(
                                Self::to_stream_compatible(
                                    mk_error_response(
                                        msg,
                                        OptRcode::SERVFAIL,
                                    ),
                                ),
                            );
                        }
                    }
                }

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
                return ControlFlow::Break(res);
            }

            true => {
                // https://datatracker.ietf.org/doc/html/rfc1996#section-4
                //   "4.8 Master Receives a NOTIFY Response from Slave
                //
                //    When a master server receives a NOTIFY response, it
                //    deletes this query from the retry queue, thus completing
                //    the "notification process" of "this" RRset change to
                //    "that" server."
                catalog
                    .notify_response_received(class, &apex_name, source)
                    .await;
            }
        }

        ControlFlow::Continue(())
    }

    fn to_stream_compatible(
        response: AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) -> Once<Ready<<Svc::Stream as Stream>::Item>> {
        once(ready(Ok(CallResult::new(response))))
    }

    fn get_relevant_question(
        msg: &Message<RequestOctets>,
    ) -> Option<Question<ParsedName<RequestOctets::Range<'_>>>> {
        if Opcode::NOTIFY == msg.header().opcode() {
            if let Some(q) = msg.first_question() {
                if q.qtype() == Rtype::SOA {
                    return Some(q);
                }
            }
        }

        None
    }

    // Based on RequestMessage::append_message_impl().
    fn copy_message(
        source: &Message<RequestOctets>,
    ) -> Result<AdditionalBuilder<StreamTarget<Svc::Target>>, CopyRecordsError>
    {
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

impl<RequestOctets, Svc> Service<RequestOctets>
    for NotifyMiddlewareSvc<RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    Svc: Service<RequestOctets> + Clone + 'static + Send + Sync + Unpin,
    Svc::Future: Send + Sync + Unpin,
    Svc::Target: Composer + Default + Send + Sync,
{
    type Target = Svc::Target;
    type Stream = MiddlewareStream<
        Svc::Future,
        Svc::Stream,
        Svc::Stream,
        Once<Ready<<Svc::Stream as Stream>::Item>>,
        <Svc::Stream as Stream>::Item,
    >;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send + Sync>>;

    fn call(&self, request: Request<RequestOctets>) -> Self::Future {
        let request = request.clone();
        let svc = self.svc.clone();
        let catalog = self.catalog.clone();
        Box::pin(async move {
            match Self::preprocess(&request, catalog).await {
                ControlFlow::Continue(()) => {
                    let stream = svc.call(request).await;
                    MiddlewareStream::IdentityStream(stream)
                }
                ControlFlow::Break(stream) => {
                    MiddlewareStream::Result(stream)
                }
            }
        })
    }
}
