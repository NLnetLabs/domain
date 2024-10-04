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
use crate::base::message_builder::AdditionalBuilder;
use crate::base::opt::{AllOptData, ComposeOptData, LongOptData, OptRecord};
use crate::base::{Message, MessageBuilder, ParsedName, Rtype, StreamTarget};
use crate::dep::octseq::Octets;
use crate::net::client::request::Error;
use crate::rdata::AllRecordData;
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
    ) -> Pin<Box<dyn Future<Output = Result<CR, Error>> + Send + Sync>>
    where
        RequestOcts: AsRef<[u8]> + Octets;
}

/// Trait for creating a reply message.
pub trait ComposeReply {
    /// Start a reply from an existing message.
    fn from_message<Octs>(msg: &Message<Octs>) -> Self
    where
        Octs: AsRef<[u8]>;

    /// Return the reply message as an AdditionalBuilder with a StreamTarget.
    fn additional_builder_stream_target(
        &self,
    ) -> AdditionalBuilder<StreamTarget<Vec<u8>>>;
}

/// Record changes to a Message for generating a reply message.
pub struct ReplyMessage {
    /// Field to store the underlying Message.
    msg: Message<Vec<u8>>,

    /// The OPT record to add if required.
    opt: Option<OptRecord<Vec<u8>>>,
}

impl ReplyMessage {
    /// Add an option that is to be included in the final message.
    fn add_opt(
        &mut self,
        opt: &impl ComposeOptData,
    ) -> Result<(), LongOptData> {
        self.opt_mut().push(opt).map_err(|e| e.unlimited_buf())
    }

    /// Returns a mutable reference to the OPT record.
    ///
    /// Adds one if necessary.
    fn opt_mut(&mut self) -> &mut OptRecord<Vec<u8>> {
        self.opt.get_or_insert_with(Default::default)
    }
}

impl ComposeReply for ReplyMessage {
    fn from_message<Octs>(msg: &Message<Octs>) -> Self
    where
        Octs: AsRef<[u8]>,
    {
        let vec = msg.as_slice().to_vec();
        let msg = Message::from_octets(vec).unwrap();
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
                let opt = opt.unwrap();
                if let AllOptData::ClientSubnet(_ecs) = opt {
                    repl.add_opt(&opt).unwrap();
                }
                if let AllOptData::ExtendedError(ref _ede) = opt {
                    repl.add_opt(&opt).unwrap();
                }
            }
        }
        repl
    }

    fn additional_builder_stream_target(
        &self,
    ) -> AdditionalBuilder<StreamTarget<Vec<u8>>> {
        let source = &self.msg;

        let mut target = MessageBuilder::from_target(
            StreamTarget::<Vec<u8>>::new(Default::default()).unwrap(),
        )
        .unwrap();

        let header = source.header();
        *target.header_mut() = header;

        let source = source.question();
        let mut target = target.additional().builder().question();
        for rr in source {
            let rr = rr.unwrap();
            target.push(rr).unwrap();
        }
        let mut source = source.answer().unwrap();
        let mut target = target.answer();
        for rr in &mut source {
            let rr = rr.unwrap();
            let rr = rr
                .into_record::<AllRecordData<_, ParsedName<_>>>()
                .unwrap()
                .unwrap();
            target.push(rr).unwrap();
        }

        let mut source = source.next_section().unwrap().unwrap();
        let mut target = target.authority();
        for rr in &mut source {
            let rr = rr.unwrap();
            let rr = rr
                .into_record::<AllRecordData<_, ParsedName<_>>>()
                .unwrap()
                .unwrap();
            target.push(rr).unwrap();
        }

        let source = source.next_section().unwrap().unwrap();
        let mut target = target.additional();
        for rr in source {
            let rr = rr.unwrap();
            if rr.rtype() == Rtype::OPT {
            } else {
                let rr = rr
                    .into_record::<AllRecordData<_, ParsedName<_>>>()
                    .unwrap()
                    .unwrap();
                target.push(rr).unwrap();
            }
        }
        if let Some(opt) = self.opt.as_ref() {
            target.push(opt.as_record()).unwrap();
        }

        target
    }
}
