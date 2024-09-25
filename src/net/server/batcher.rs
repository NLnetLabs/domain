//! Resource record batching for response stream splitting.
//!
//! Some DNS requests can result in very large responses that have to be split
//! across multiple messages to be sent back to the client. This applies
//! primarily, if not solely, to responses to AXFR ([RFC 5936]) and IXFR ([RFC
//! 1995]) requests.
//!
//! For example RFC 5936 section 2.2 AXFR Response includes the following
//! paragraph:
//!
//!    >  _"Each AXFR response message SHOULD contain a sufficient number of
//!    >  RRs to reasonably amortize the per-message overhead, up to the
//!    >  largest number that will fit within a DNS message (taking the
//!    >  required content of the other sections into account, as described
//!    >  below)."_
//!
//! This module defines a [ResourceRecordbatcher] trait and a
//! [CallbackBatcher] implementation of the trait, which can split be used a
//! stream of resource records into "batches" filling each DNS response
//! message as much as possible one message at a time from a received stream
//! of resource records.
//!
//! # Usage
//!
//! 1. `impl Callbacks` for a struct providing your own `batch_ready()` and
//!    `record_pushed()` fn implementations.
//!
//! 2. Create an instance of `CallbackBatcher` generic over your `Callbacks`
//!    impl type.
//!
//! 3. Call `CallbackBatcher::push()` repeatedly until no more resource
//!    records are left to push for the current response.
//!
//! 4. Call `CallbackBatcher::finish()` to ensure that a last partial response
//!    is also completely handled.
//!
//! [RFC 1995]: https://www.rfc-editor.org/info/rfc1995
//! [RFC 5936]: https://www.rfc-editor.org/info/rfc5936
//! [ResourceRecordBatcher]: ResourceRecordBatcher
//! [CallbackBatcher]: CallbackBatcher  
use core::marker::PhantomData;

use std::fmt::Debug;
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

/// The result of attempting to push a resource record into a
/// [ResourceRecordBatcher].
pub enum PushResult<Target> {
    /// The resource record was successfully pushed and more will fit.
    PushedAndReadyForMore,

    /// The resource record was successfully pushed and no more will fit.
    PushedAndLimitReached(AnswerBuilder<StreamTarget<Target>>),

    /// The resource record was not pushed because the message is full.
    NotPushedMessageFull(AnswerBuilder<StreamTarget<Target>>),

    /// The resource record was not pushed but trying again might work.
    Retry,
}

//------------ ResourceRecordBatcher ------------------------------------------

/// An accumulator of resource records into one or more DNS responses.
pub trait ResourceRecordBatcher<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    /// The type returned on error.
    type Error: From<PushError> + Debug;

    /// Attempt to push a single resource record into a response message.
    #[allow(clippy::result_unit_err)]
    fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<PushResult<Target>, Self::Error>;

    /// Signal that the last resource record has been pushed for this response
    /// sequence.
    #[allow(clippy::result_unit_err)]
    fn finish(&mut self) -> Result<(), Self::Error>;

    /// Creates a new `AnswerBuilder` for the given request message.
    ///
    /// The default implementation sets the RCODE of the new builder to
    /// `NOERROR`.
    fn mk_answer_builder(
        &self,
        msg: &Message<RequestOctets>,
    ) -> Result<AnswerBuilder<StreamTarget<Target>>, PushError> {
        let builder = mk_builder_for_target();
        builder.start_answer(msg, Rcode::NOERROR)
    }
}

//------------ Callbacks ------------------------------------------------------

/// A set of callback functions for use with [`CallbackBatcher`].
pub trait Callbacks<RequestOctets, Target, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    /// The type returned on error.
    type Error: From<PushError> + Debug;

    /// Prepare a message builder to push records into.
    fn batch_started(
        _state: &T,
        msg: &Message<RequestOctets>,
    ) -> Result<AnswerBuilder<StreamTarget<Target>>, PushError> {
        let builder = mk_builder_for_target();
        let answer = builder.start_answer(msg, Rcode::NOERROR)?;
        Ok(answer)
    }

    /// A record has been pushed. Is the message now full?
    ///
    /// Return true if it is full, false if there is still space.
    fn record_pushed(
        _state: &T,
        _answer: &AnswerBuilder<StreamTarget<Target>>,
    ) -> bool {
        false
    }

    /// Do something with the completed message.
    #[allow(clippy::result_unit_err)]
    fn batch_ready(
        state: &T,
        answer: AnswerBuilder<StreamTarget<Target>>,
        finished: bool,
    ) -> Result<(), Self::Error>;
}

//------------ CallbackBatcher ------------------------------------------------

/// A [`ResourceRecordBatcher`] impl that delegates work to callacks.
pub struct CallbackBatcher<RequestOctets, Target, C, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    C: Callbacks<RequestOctets, Target, T>,
{
    /// The request message being responded to.
    ///
    /// Needed for constructing response messages.
    req_msg: Arc<Message<RequestOctets>>,

    /// The current answer builder in use.
    answer: Option<Result<AnswerBuilder<StreamTarget<Target>>, PushError>>,

    /// User defined callback specific state.
    callback_state: T,

    _phantom: PhantomData<C>,
}

impl<RequestOctets, Target, C, T> CallbackBatcher<RequestOctets, Target, C, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    C: Callbacks<RequestOctets, Target, T>,
{
    /// Creates a new instance for building responses to the given request.
    ///
    /// Delegates certain parts of the task to the callbacks supplied via
    /// generic type `C` which must implement the [`Callbacks`] trait.
    ///
    /// Any state that should be forwarded to the callbacks can be provided
    /// using the `callback_state` parameter.
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

    /// Returns the callback specific state.
    ///
    /// This convenience method returns a reference to the callback specific
    /// state that was supplied when the instance was created by calling
    /// [`new()`][Self::new].
    pub fn callback_state(&self) -> &T {
        &self.callback_state
    }
}

impl<RequestOctets, Target, C, T> CallbackBatcher<RequestOctets, Target, C, T>
where
    RequestOctets: Octets,
    Target: Composer + Default,
    C: Callbacks<RequestOctets, Target, T>,
{
    /// Try and push a resource record into the current response.
    ///
    /// Invokes [`Callbacks::batch_ready()`] on success.
    fn try_push(
        &mut self,
        record: &impl ComposeRecord,
    ) -> Result<PushResult<Target>, C::Error> {
        match self.push_ref(record)? {
            PushResult::PushedAndLimitReached(builder) => {
                C::batch_ready(&self.callback_state, builder, false)?;
                Ok(PushResult::PushedAndReadyForMore)
            }
            PushResult::NotPushedMessageFull(builder) => {
                C::batch_ready(&self.callback_state, builder, false)?;
                Ok(PushResult::Retry)
            }
            other => Ok(other),
        }
    }

    /// Push a resource record into the current response.
    ///
    /// Invokes [`Callbacks::batch_started()`] and
    /// [`Callbacks::record_pushed()`] if appropriate.
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
    type Error = C::Error;

    fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<PushResult<Target>, Self::Error> {
        match self.try_push(&record) {
            Ok(PushResult::Retry) => self.try_push(&record),
            other => other,
        }
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        if let Some(builder) = self.answer.take() {
            C::batch_ready(&self.callback_state, builder.unwrap(), true)
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
    /// Notes via trace logging if an in-progress answer is dropped.
    fn drop(&mut self) {
        if self.answer.is_some() {
            trace!("Dropping unfinished batcher, was that intentional or did you forget to call finish()?");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{MessageBuilder, Name};
    use crate::rdata::Txt;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::vec::Vec;

    #[test]
    fn batch_of_zero() {
        let mut batcher = mk_counting_batcher();
        batcher.callback_state().assert_eq(0, 0, 0);
        batcher.finish().unwrap();
        batcher.callback_state().assert_eq(0, 0, 0);
    }

    #[test]
    fn batch_of_one() {
        let mut batcher = mk_counting_batcher();
        batcher.push(mk_dummy_rr(&[])).unwrap();
        batcher.callback_state().assert_eq(1, 1, 0);
        batcher.finish().unwrap();
        batcher.callback_state().assert_eq(0, 1, 1);
    }

    #[test]
    fn batch_of_one_very_large_rr() {
        let mut batcher = mk_counting_batcher();
        batcher.push(mk_dummy_rr(&vec![0; 65000])).unwrap();
        batcher.callback_state().assert_eq(1, 1, 0);
        batcher.finish().unwrap();
        batcher.callback_state().assert_eq(0, 1, 1);
    }

    #[test]
    fn batch_of_many_small_rrs() {
        let mut batcher = mk_counting_batcher();
        for _ in 0..1000 {
            batcher.push(mk_dummy_rr(&[0; 10])).unwrap();
        }
        batcher.callback_state().assert_eq(1000, 1000, 0);
        batcher.finish().unwrap();
        batcher.callback_state().assert_eq(0, 1000, 1);
    }

    #[test]
    fn batch_of_two_too_big_rrs() {
        let mut batcher = mk_counting_batcher();
        batcher.push(mk_dummy_rr(&vec![0; 65000])).unwrap();
        batcher.callback_state().assert_eq(1, 1, 0);
        batcher.push(mk_dummy_rr(&vec![0; 1000])).unwrap();
        batcher.callback_state().assert_eq(1, 2, 1);
        batcher.finish().unwrap();
        batcher.callback_state().assert_eq(0, 2, 2);
    }

    fn mk_counting_batcher(
    ) -> CallbackBatcher<Vec<u8>, Vec<u8>, BatchCounter, Arc<TestCounters>>
    {
        let req = Arc::new(MessageBuilder::new_vec().into_message());
        let cnt = Arc::new(TestCounters::new());
        CallbackBatcher::new(req, cnt)
    }

    fn mk_dummy_rr(text: &[u8]) -> impl ComposeRecord {
        (
            Name::root_vec(),
            0,
            Txt::<Vec<u8>>::build_from_slice(text).unwrap(),
        )
    }

    //------------ TestCounters -----------------------------------------------

    #[derive(Default)]
    struct TestCounters {
        num_rrs_in_last_batch: AtomicU64,
        num_total_rrs: AtomicU64,
        num_batches: AtomicU64,
    }

    impl TestCounters {
        fn new() -> Self {
            Self::default()
        }

        fn assert_eq(
            &self,
            num_rrs_in_last_batch: u64,
            num_total_rrs: u64,
            num_batches: u64,
        ) {
            assert_eq!(
                self.num_rrs_in_last_batch.load(Ordering::SeqCst),
                num_rrs_in_last_batch
            );
            assert_eq!(
                self.num_total_rrs.load(Ordering::SeqCst),
                num_total_rrs
            );
            assert_eq!(self.num_batches.load(Ordering::SeqCst), num_batches);
        }
    }

    //------------ TestCallbacks ----------------------------------------------

    struct BatchCounter;

    impl From<PushError> for () {
        fn from(_: PushError) -> Self {}
    }

    impl Callbacks<Vec<u8>, Vec<u8>, Arc<TestCounters>> for BatchCounter {
        type Error = ();

        fn batch_ready(
            counters: &Arc<TestCounters>,
            answer: AnswerBuilder<StreamTarget<Vec<u8>>>,
            _finished: bool,
        ) -> Result<(), ()> {
            counters.num_batches.fetch_add(1, Ordering::SeqCst);
            counters.num_rrs_in_last_batch.store(0, Ordering::SeqCst);
            eprintln!("Answer byte length: {}", answer.as_slice().len());
            Ok(())
        }

        fn record_pushed(
            counters: &Arc<TestCounters>,
            _answer: &AnswerBuilder<StreamTarget<Vec<u8>>>,
        ) -> bool {
            counters
                .num_rrs_in_last_batch
                .fetch_add(1, Ordering::SeqCst);
            counters.num_total_rrs.fetch_add(1, Ordering::SeqCst);
            false
        }
    }
}
