// Single reply service

use super::message::RequestNG;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::opt::AllOptData;
use crate::base::opt::ComposeOptData;
use crate::base::opt::LongOptData;
use crate::base::opt::OptRecord;
use crate::base::Message;
use crate::base::MessageBuilder;
use crate::base::ParsedName;
use crate::base::Rtype;
use crate::base::StreamTarget;
use crate::net::client::request::Error;
use crate::dep::octseq::Octets;
use crate::rdata::AllRecordData;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::vec::Vec;

pub trait SingleService<RequestOcts, CR> {
    type Target;

    fn call(
        &self,
        request: RequestNG<RequestOcts>,
    ) -> Pin<Box<dyn Future<Output = Result<CR, Error>> + Send + Sync>>
    where
        RequestOcts: AsRef<[u8]> + Octets;
}

pub trait ComposeReply {
    fn from_message<Octs>(msg: &Message<Octs>) -> Self
    where
        Octs: AsRef<[u8]>;
    fn additional_builder_stream_target(
        &self,
    ) -> AdditionalBuilder<StreamTarget<Vec<u8>>>;
}

pub struct ReplyMessage {
    msg: Message<Vec<u8>>,

    /// The OPT record to add if required.
    opt: Option<OptRecord<Vec<u8>>>,
}

impl ReplyMessage {
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
                /*
                            let rr = rr.into_record::<Opt<_>>().unwrap().unwrap();
                            let opt_record = OptRecord::from_record(rr);
                            target
                                .opt(|newopt| {
                                newopt
                                    .set_udp_payload_size(opt_record.udp_payload_size());
                                newopt.set_version(opt_record.version());
                                newopt.set_dnssec_ok(opt_record.dnssec_ok());

                                // Copy the transitive options that we support.
                                for option in opt_record.opt().iter::<AllOptData<_, _>>()
                                {
                                    let option = option.unwrap();
                                    if let AllOptData::ExtendedError(_) = option {
                                    newopt.push(&option).unwrap();
                                    }
                                }
                                Ok(())
                                })
                                .unwrap();
                */
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
