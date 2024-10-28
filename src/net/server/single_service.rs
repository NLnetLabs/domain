//! This module provides the as simple service interface for services that
//! provide (at most) a single response.
//!
//! The simple service is represented by the trait [SingleService].
//! Additionally, this module provide a new trait [ComposeReply] that
//! helps generating reply messages and [ReplyMessage] an implementation of
//! ComposeReply.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use super::message::Request;
use super::service::ServiceError;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::opt::{
    AllOptData, ComposeOptData, LongOptData, OptRecord, UnknownRecordData,
};
use crate::base::{Message, MessageBuilder, Rtype, StreamTarget};
use crate::dep::octseq::Octets;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::vec::Vec;

/// Trait for a service that results in a single response.
pub trait SingleService<RequestOcts: Send + Sync, CR> {
    /// Call the service with a request message.
    ///
    /// The service returns a boxed future.
    fn call(
        &self,
        request: Request<RequestOcts>,
    ) -> Pin<Box<dyn Future<Output = Result<CR, ServiceError>> + Send + Sync>>
    where
        RequestOcts: AsRef<[u8]> + Octets;
}

/// Trait for creating a reply message.
pub trait ComposeReply {
    /// Start a reply from an existing message.
    fn from_message<Octs>(msg: &Message<Octs>) -> Result<Self, ServiceError>
    where
        Octs: AsRef<[u8]>,
        Self: Sized;

    /// Add an EDNS option.
    fn add_opt(
        &mut self,
        opt: &impl ComposeOptData,
    ) -> Result<(), LongOptData>;

    /// Return the reply message as an AdditionalBuilder with a StreamTarget.
    fn additional_builder_stream_target(
        &self,
    ) -> Result<AdditionalBuilder<StreamTarget<Vec<u8>>>, ServiceError>;
}

/// Record changes to a Message for generating a reply message.
#[derive(Debug)]
pub struct ReplyMessage {
    /// Field to store the underlying Message.
    msg: Message<Vec<u8>>,

    /// The OPT record to add if required.
    opt: Option<OptRecord<Vec<u8>>>,
}

impl ReplyMessage {
    /// Add an option that is to be included in the final message.
    fn add_opt_impl(&mut self, opt: &impl ComposeOptData) {
        self.opt_mut().push(opt).expect("push should not fail");
    }

    /// Returns a mutable reference to the OPT record.
    ///
    /// Adds one if necessary.
    fn opt_mut(&mut self) -> &mut OptRecord<Vec<u8>> {
        self.opt.get_or_insert_with(Default::default)
    }
}

impl ComposeReply for ReplyMessage {
    fn from_message<Octs>(msg: &Message<Octs>) -> Result<Self, ServiceError>
    where
        Octs: AsRef<[u8]>,
    {
        let vec = msg.as_slice().to_vec();
        let msg = Message::from_octets(vec)
            .expect("creating a Message from a Message should not fail");
        let mut repl = Self { msg, opt: None };

        // As an example, copy any ECS option from the message.
        // though this should be done in a separate ECS plugin.
        let msg = repl.msg.clone();
        if let Some(optrec) = msg.opt() {
            // Copy opt header.
            let opt = repl.opt_mut();
            opt.set_udp_payload_size(optrec.udp_payload_size());
            //opt.set_version(optrec.version());
            opt.set_dnssec_ok(optrec.dnssec_ok());

            for opt in optrec.opt().iter::<AllOptData<_, _>>() {
                let opt = opt?;
                if let AllOptData::ClientSubnet(_ecs) = opt {
                    repl.add_opt_impl(&opt);
                }
                if let AllOptData::ExtendedError(ref _ede) = opt {
                    repl.add_opt_impl(&opt);
                }
            }
        }
        Ok(repl)
    }

    fn add_opt(
        &mut self,
        opt: &impl ComposeOptData,
    ) -> Result<(), LongOptData> {
        self.add_opt_impl(opt);
        Ok(())
    }

    fn additional_builder_stream_target(
        &self,
    ) -> Result<AdditionalBuilder<StreamTarget<Vec<u8>>>, ServiceError> {
        let source = &self.msg;

        let mut target = MessageBuilder::from_target(
            StreamTarget::<Vec<u8>>::new(Default::default())
                .expect("new StreamTarget should not fail"),
        )
        .expect("new MessageBuilder should not fail");

        let header = source.header();
        *target.header_mut() = header;

        let source = source.question();
        let mut target = target.additional().builder().question();
        for rr in source {
            let rr = rr?;
            target.push(rr).expect("push should not fail");
        }
        let mut source = source.answer()?;
        let mut target = target.answer();
        for rr in &mut source {
            let rr = rr?;
            let rr = rr
                .into_record::<UnknownRecordData<_>>()?
                .expect("UnknownRecordData should not fail");
            target.push(rr).expect("push should not fail");
        }

        let mut source = source
            .next_section()?
            .expect("authority section should be present");
        let mut target = target.authority();
        for rr in &mut source {
            let rr = rr?;
            let rr = rr
                .into_record::<UnknownRecordData<_>>()?
                .expect("UnknownRecordData should not fail");
            target.push(rr).expect("push should not fail");
        }

        let source = source
            .next_section()?
            .expect("additional section should be present");
        let mut target = target.additional();
        for rr in source {
            let rr = rr?;
            if rr.rtype() == Rtype::OPT {
            } else {
                let rr = rr
                    .into_record::<UnknownRecordData<_>>()?
                    .expect("UnknownRecordData should not fail");
                target.push(rr).expect("push should not fail");
            }
        }
        if let Some(opt) = self.opt.as_ref() {
            target.push(opt.as_record()).expect("push should not fail");
        }

        Ok(target)
    }
}
