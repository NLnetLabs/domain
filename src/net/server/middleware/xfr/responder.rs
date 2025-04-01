use std::sync::Arc;

use bytes::Bytes;
use octseq::Octets;
use tokio::sync::mpsc::{Receiver, UnboundedSender};
use tokio::sync::Semaphore;
use tracing::{debug, error};

use crate::base::iana::OptRcode;
use crate::base::rdata::RecordData;
use crate::base::wire::Composer;
use crate::base::{Message, Name, Rtype};
use crate::net::server::batcher::ResourceRecordBatcher;
use crate::net::server::middleware::xfr::util::add_to_stream;
use crate::net::server::service::ServiceResult;
use crate::net::server::util::mk_builder_for_target;
use crate::zonetree::{Answer, SharedRrset};

use super::batcher::{BatchReadyError, XfrRrBatcher};

//------------ BatchingRrResponder ---------------------------------------------

pub struct BatchingRrResponder<RequestOctets, Target> {
    msg: Arc<Message<RequestOctets>>,
    zone_soa_answer: Answer,
    batcher_rx: Receiver<(Name<Bytes>, SharedRrset)>,
    response_tx: UnboundedSender<ServiceResult<Target>>,
    compatibility_mode: bool,
    soft_byte_limit: usize,
    must_fit_in_single_message: bool,
    batcher_semaphore: Arc<Semaphore>,
}

impl<RequestOctets, Target> BatchingRrResponder<RequestOctets, Target>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    Target: Composer + Default + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        msg: Arc<Message<RequestOctets>>,
        zone_soa_answer: Answer,
        batcher_rx: Receiver<(Name<Bytes>, SharedRrset)>,
        response_tx: UnboundedSender<ServiceResult<Target>>,
        compatibility_mode: bool,
        soft_byte_limit: usize,
        must_fit_in_single_message: bool,
        batcher_semaphore: Arc<Semaphore>,
    ) -> Self {
        Self {
            msg,
            zone_soa_answer,
            batcher_rx,
            response_tx,
            compatibility_mode,
            soft_byte_limit,
            must_fit_in_single_message,
            batcher_semaphore,
        }
    }

    pub async fn run(mut self) -> Result<(), OptRcode> {
        // Limit the number of concurrently running XFR batching
        // operations.
        if self.batcher_semaphore.acquire().await.is_err() {
            error!("Internal error: Failed to acquire XFR batcher semaphore");
            return Err(OptRcode::SERVFAIL);
        }

        // SAFETY: msg.sole_question() was already checked in
        // get_relevant_question().
        let qclass = self.msg.sole_question().unwrap().qclass();

        // Note: NSD apparently uses name compresson on AXFR responses
        // because AXFR responses they typically contain lots of
        // alphabetically ordered duplicate names which compress well. NSD
        // limits AXFR responses to 16,383 bytes because DNS name
        // compression uses a 14-bit offset (2^14-1=16383) from the start
        // of the message to the first occurence of a name instead of
        // repeating the name, and name compression is less effective
        // over 16383 bytes. (Credit: Wouter Wijngaards)
        //
        // TODO: Once we start supporting name compression in responses decide
        // if we want to behave the same way.

        let hard_rr_limit = match self.compatibility_mode {
            true => Some(1),
            false => None,
        };

        let mut batcher = XfrRrBatcher::build(
            self.msg.clone(),
            self.response_tx.clone(),
            Some(self.soft_byte_limit),
            hard_rr_limit,
            self.must_fit_in_single_message,
        );

        let mut last_rr_rtype = None;

        while let Some((owner, rrset)) = self.batcher_rx.recv().await {
            for rr in rrset.data() {
                last_rr_rtype = Some(rr.rtype());

                if let Err(err) =
                    batcher.push((owner.clone(), qclass, rrset.ttl(), rr))
                {
                    match err {
                        BatchReadyError::MustFitInSingleMessage => {
                            // https://datatracker.ietf.org/doc/html/rfc1995#section-2
                            // 2. Brief Description of the Protocol
                            //    ..
                            //    "If the UDP reply does not fit, the
                            //     query is responded to with a single SOA
                            //     record of the server's current version
                            //     to inform the client that a TCP query
                            //     should be initiated."
                            debug_assert!(self.must_fit_in_single_message);
                            debug!("Responding to IXFR with single SOA because response does not fit in a single UDP reply");

                            let builder = mk_builder_for_target();

                            let resp = self
                                .zone_soa_answer
                                .to_message(&self.msg, builder);

                            add_to_stream(resp, &self.response_tx);

                            return Ok(());
                        }

                        BatchReadyError::PushError(err) => {
                            error!("Internal error: Failed to send RR to batcher: {err}");
                            return Err(OptRcode::SERVFAIL);
                        }

                        BatchReadyError::SendError => {
                            debug!("Batcher was unable to send completed batch. Was the receiver dropped?");
                            return Err(OptRcode::SERVFAIL);
                        }
                    }
                }
            }
        }

        if let Err(err) = batcher.finish() {
            debug!("Batcher was unable to finish: {err}");
            return Err(OptRcode::SERVFAIL);
        }

        if last_rr_rtype != Some(Rtype::SOA) {
            error!(
                "Internal error: Last RR was {}, expected SOA",
                last_rr_rtype.unwrap()
            );
            return Err(OptRcode::SERVFAIL);
        }

        Ok(())
    }
}
