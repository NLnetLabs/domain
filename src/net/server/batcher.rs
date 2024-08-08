//------------ ResourceRecordBatcher ------------------------------------------

use core::marker::PhantomData;

use std::sync::Arc;

use octseq::Octets;
use tracing::trace;

use crate::base::iana::Rcode;
use crate::base::message_builder::{AnswerBuilder, PushError};
use crate::base::record::ComposeRecord;
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};

use super::util::mk_builder_for_target;

//----------- PushResult ------------------------------------------------------

pub enum PushResult<Target> {
    PushedAndReadyForMore,
    PushedAndLimitReached(AnswerBuilder<StreamTarget<Target>>),
    NotPushedMessageFull(AnswerBuilder<StreamTarget<Target>>),
    Retry,
}

//------------ ResourceRecordBatcher ------------------------------------------

pub trait ResourceRecordBatcher<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    #[allow(clippy::result_unit_err)]
    fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<PushResult<Target>, ()>;

    #[allow(clippy::result_unit_err)]
    fn finish(&mut self) -> Result<(), ()>;

    fn mk_answer_builder(
        &self,
        msg: &Message<RequestOctets>,
    ) -> Result<AnswerBuilder<StreamTarget<Target>>, PushError> {
        let builder = mk_builder_for_target();
        builder.start_answer(msg, Rcode::NOERROR)
    }
}

//------------ Callbacks ------------------------------------------------------

pub trait Callbacks<RequestOctets, Target, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    fn batch_started(
        _state: &T,
        msg: &Message<RequestOctets>,
    ) -> Result<AnswerBuilder<StreamTarget<Target>>, PushError> {
        let builder = mk_builder_for_target();
        let answer = builder.start_answer(msg, Rcode::NOERROR)?;
        Ok(answer)
    }

    fn record_pushed(
        _state: &T,
        _answer: &AnswerBuilder<StreamTarget<Target>>,
    ) -> bool {
        false
    }

    #[allow(clippy::result_unit_err)]
    fn batch_ready(
        _state: &T,
        _answer: AnswerBuilder<StreamTarget<Target>>,
    ) -> Result<(), ()>;
}

//------------ CallbackBatcher ------------------------------------------------

pub struct CallbackBatcher<RequestOctets, Target, C, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    C: Callbacks<RequestOctets, Target, T>,
{
    req_msg: Arc<Message<RequestOctets>>,
    answer: Option<Result<AnswerBuilder<StreamTarget<Target>>, PushError>>,
    callback_state: T,
    _phantom: PhantomData<C>,
}

impl<RequestOctets, Target, C, T> CallbackBatcher<RequestOctets, Target, C, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    C: Callbacks<RequestOctets, Target, T>,
{
    pub fn new(
        req_msg: Arc<Message<RequestOctets>>,
        callback_state: T,
    ) -> Self {
        Self {
            req_msg,
            answer: None,
            callback_state,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, Target, C, T> CallbackBatcher<RequestOctets, Target, C, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    C: Callbacks<RequestOctets, Target, T>,
{
    fn try_push(
        &mut self,
        record: &impl ComposeRecord,
    ) -> Result<PushResult<Target>, ()> {
        match self.push_ref(record).map_err(|_| ())? {
            PushResult::PushedAndLimitReached(builder) => {
                C::batch_ready(&self.callback_state, builder)?;
                Ok(PushResult::PushedAndReadyForMore)
            }
            PushResult::NotPushedMessageFull(builder) => {
                C::batch_ready(&self.callback_state, builder)?;
                Ok(PushResult::Retry)
            }
            other => Ok(other),
        }
    }

    fn push_ref(
        &mut self,
        record: &impl ComposeRecord,
    ) -> Result<PushResult<Target>, PushError> {
        let req_msg = &self.req_msg;

        if self.answer.is_none() {
            self.answer =
                Some(C::batch_started(&self.callback_state, req_msg));
        }

        let mut answer = self.answer.take().unwrap()?;

        let res = answer.push_ref(record);
        let ancount = answer.counts().ancount();

        match res {
            Ok(()) if C::record_pushed(&self.callback_state, &answer) => {
                // Push succeeded but the message is as full as the caller
                // allows, pass it back to the caller to process.
                Ok(PushResult::PushedAndLimitReached(answer))
            }

            Err(_) if ancount > 0 => {
                // Push failed because the message is full, pass it back to
                // the caller to process.
                Ok(PushResult::NotPushedMessageFull(answer))
            }

            Err(err) => {
                // We expect to be able to add at least one answer to the message.
                Err(err)
            }

            Ok(()) => {
                // Record has been added, keep the answer builder for the next push.
                self.answer = Some(Ok(answer));
                Ok(PushResult::PushedAndReadyForMore)
            }
        }
    }
}

//--- ResourceRecordBatcher

impl<RequestOctets, Target, C, T> ResourceRecordBatcher<RequestOctets, Target>
    for CallbackBatcher<RequestOctets, Target, C, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    C: Callbacks<RequestOctets, Target, T>,
{
    fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<PushResult<Target>, ()> {
        match self.try_push(&record) {
            Ok(PushResult::Retry) => self.try_push(&record),
            other => other,
        }
    }

    fn finish(&mut self) -> Result<(), ()> {
        if let Some(builder) = self.answer.take() {
            C::batch_ready(&self.callback_state, builder.unwrap())
        } else {
            Ok(())
        }
    }

    fn mk_answer_builder(
        &self,
        msg: &Message<RequestOctets>,
    ) -> Result<AnswerBuilder<StreamTarget<Target>>, PushError> {
        C::batch_started(&self.callback_state, msg)
    }
}

//--- Drop

impl<RequestOctets, Target, C, T> Drop
    for CallbackBatcher<RequestOctets, Target, C, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    C: Callbacks<RequestOctets, Target, T>,
{
    fn drop(&mut self) {
        if self.answer.is_some() {
            trace!("Dropping unfinished batcher, was that intentional or did you forget to call finish()?");
        }
    }
}
