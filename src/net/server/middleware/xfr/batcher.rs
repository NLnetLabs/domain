use core::marker::PhantomData;

use std::sync::Arc;

use octseq::Octets;
use tokio::sync::mpsc::UnboundedSender;
use tracing::trace;

use crate::base::iana::{Opcode, Rcode};
use crate::base::message_builder::{
    AdditionalBuilder, AnswerBuilder, PushError,
};
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};
use crate::net::server::batcher::{
    CallbackBatcher, Callbacks, ResourceRecordBatcher,
};
use crate::net::server::service::{CallResult, ServiceResult};
use crate::net::server::util::mk_builder_for_target;

//------------ BatchReadyError ------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum BatchReadyError {
    PushError(PushError),

    SendError,

    MustFitInSingleMessage,
}

//--- Display

impl std::fmt::Display for BatchReadyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BatchReadyError::MustFitInSingleMessage => {
                f.write_str("MustFitInSingleMessage")
            }
            BatchReadyError::PushError(err) => {
                f.write_fmt(format_args!("PushError: {err}"))
            }
            BatchReadyError::SendError => f.write_str("SendError"),
        }
    }
}

//--- From<PushError>

impl From<PushError> for BatchReadyError {
    fn from(err: PushError) -> Self {
        Self::PushError(err)
    }
}

//------------ XfrRrBatcher ---------------------------------------------------

pub struct XfrRrBatcher<RequestOctets, Target> {
    _phantom: PhantomData<(RequestOctets, Target)>,
}

impl<RequestOctets, Target> XfrRrBatcher<RequestOctets, Target>
where
    RequestOctets: Octets + Sync + Send + 'static,
    Target: Composer + Default + Send + 'static,
{
    pub fn build(
        req_msg: Arc<Message<RequestOctets>>,
        sender: UnboundedSender<ServiceResult<Target>>,
        soft_byte_limit: Option<usize>,
        hard_rr_limit: Option<u16>,
        must_fit_in_single_message: bool,
    ) -> impl ResourceRecordBatcher<RequestOctets, Target, Error = BatchReadyError>
    {
        let cb_state = CallbackState::new(
            req_msg.clone(),
            sender,
            soft_byte_limit,
            hard_rr_limit,
            must_fit_in_single_message,
        );

        CallbackBatcher::<
            RequestOctets,
            Target,
            Self,
            CallbackState<RequestOctets, Target>,
        >::new(req_msg, cb_state)
    }
}

impl<RequestOctets, Target> XfrRrBatcher<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    fn set_axfr_header(
        msg: &Message<RequestOctets>,
        additional: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2.1
        // 2.2.1: Header Values
        //
        // "These are the DNS message header values for AXFR responses.
        //
        //     ID          MUST be copied from request -- see Note a)
        //
        //     QR          MUST be 1 (Response)
        //
        //     OPCODE      MUST be 0 (Standard Query)
        //
        //     Flags:
        //        AA       normally 1 -- see Note b)
        //        TC       MUST be 0 (Not truncated)
        //        RD       RECOMMENDED: copy request's value; MAY be set to 0
        //        RA       SHOULD be 0 -- see Note c)
        //        Z        "mbz" -- see Note d)
        //        AD       "mbz" -- see Note d)
        //        CD       "mbz" -- see Note d)"
        let header = additional.header_mut();

        // Note: MandatoryMiddlewareSvc will also "fix" ID and QR, so strictly
        // speaking this isn't necessary, but as a caller might not use
        // MandatoryMiddlewareSvc we do it anyway to try harder to conform to
        // the RFC.
        header.set_id(msg.header().id());
        header.set_qr(true);

        header.set_opcode(Opcode::QUERY);
        header.set_aa(true);
        header.set_tc(false);
        header.set_rd(msg.header().rd());
        header.set_ra(false);
        header.set_z(false);
        header.set_ad(false);
        header.set_cd(false);
    }
}

//--- Callbacks

impl<RequestOctets, Target>
    Callbacks<RequestOctets, Target, CallbackState<RequestOctets, Target>>
    for XfrRrBatcher<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    type Error = BatchReadyError;

    fn batch_started(
        cb_state: &CallbackState<RequestOctets, Target>,
        msg: &Message<RequestOctets>,
    ) -> Result<AnswerBuilder<StreamTarget<Target>>, PushError> {
        let mut builder = mk_builder_for_target();
        if let Some(limit) = cb_state.soft_byte_limit {
            builder.set_push_limit(limit);
        }
        let answer = builder.start_answer(msg, Rcode::NOERROR)?;
        Ok(answer)
    }

    fn batch_ready(
        cb_state: &CallbackState<RequestOctets, Target>,
        builder: AnswerBuilder<StreamTarget<Target>>,
        finished: bool,
    ) -> Result<(), Self::Error> {
        if !finished && cb_state.must_fit_in_single_message {
            return Err(BatchReadyError::MustFitInSingleMessage);
        }

        trace!("Sending RR batch");
        let mut additional = builder.additional();
        Self::set_axfr_header(&cb_state.req_msg, &mut additional);
        let call_result = Ok(CallResult::new(additional));
        cb_state
            .sender
            .send(call_result)
            .map_err(|_unsent_msg| BatchReadyError::SendError)
    }

    fn record_pushed(
        cb_state: &CallbackState<RequestOctets, Target>,
        answer: &AnswerBuilder<StreamTarget<Target>>,
    ) -> bool {
        if let Some(hard_rr_limit) = cb_state.hard_rr_limit {
            let ancount = answer.counts().ancount();
            let limit_reached = ancount == hard_rr_limit;
            trace!(
                "ancount={ancount}, hard_rr_limit={hard_rr_limit}, limit_reached={limit_reached}");
            limit_reached
        } else {
            false
        }
    }
}

//------------ CallbackState --------------------------------------------------

struct CallbackState<RequestOctets, Target> {
    req_msg: Arc<Message<RequestOctets>>,
    sender: UnboundedSender<ServiceResult<Target>>,
    soft_byte_limit: Option<usize>,
    hard_rr_limit: Option<u16>,
    must_fit_in_single_message: bool,
}

impl<RequestOctets, Target> CallbackState<RequestOctets, Target> {
    fn new(
        req_msg: Arc<Message<RequestOctets>>,
        sender: UnboundedSender<ServiceResult<Target>>,
        soft_byte_limit: Option<usize>,
        hard_rr_limit: Option<u16>,
        must_fit_in_single_message: bool,
    ) -> Self {
        Self {
            req_msg,
            sender,
            soft_byte_limit,
            hard_rr_limit,
            must_fit_in_single_message,
        }
    }
}
