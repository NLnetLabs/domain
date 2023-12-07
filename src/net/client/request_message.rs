//! Simple object that implements the ComposeRequest trait.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::base::Header;
use crate::base::Message;
use crate::base::MessageBuilder;
use crate::base::ParsedDname;
use crate::base::Rtype;
use crate::base::StaticCompressor;
use crate::dep::octseq::Octets;
use crate::net::client::compose_request::ComposeRequest;
use crate::net::client::compose_request::OptTypes;
use crate::net::client::error::Error;
use crate::rdata::AllRecordData;

use std::boxed::Box;
use std::fmt::Debug;
use std::vec::Vec;

#[derive(Clone, Debug)]
/// Object that implements the ComposeRequest trait for a Message object.
pub struct RequestMessage<Octs: AsRef<[u8]>> {
    /// Base message.
    msg: Message<Octs>,

    /// New header.
    header: Header,

    /// Collection of EDNS options to add.
    opts: Vec<OptTypes>,

    /// UDP payload size.
    udp_payload_size: Option<u16>,
}

impl<Octs: AsRef<[u8]> + Debug + Octets> RequestMessage<Octs> {
    /// Create a new BMB object.
    pub fn new(msg: Message<Octs>) -> Self {
        let header = msg.header();
        Self {
            msg,
            header,
            opts: Vec::new(),
            udp_payload_size: None,
        }
    }

    /// Create new message based on the changes to the base message.
    fn to_message_impl(&self) -> Result<Message<Vec<u8>>, Error> {
        let source = &self.msg;

        let mut target =
            MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
                .expect("Vec is expected to have enough space");
        let target_hdr = target.header_mut();
        target_hdr.set_flags(self.header.flags());
        target_hdr.set_opcode(self.header.opcode());
        target_hdr.set_rcode(self.header.rcode());
        target_hdr.set_id(self.header.id());

        let source = source.question();
        let mut target = target.question();
        for rr in source {
            let rr = rr.map_err(|_e| Error::MessageParseError)?;
            target
                .push(rr)
                .map_err(|_e| Error::MessageBuilderPushError)?;
        }
        let mut source =
            source.answer().map_err(|_e| Error::MessageParseError)?;
        let mut target = target.answer();
        for rr in &mut source {
            let rr = rr.map_err(|_e| Error::MessageParseError)?;
            let rr = rr
                .into_record::<AllRecordData<_, ParsedDname<_>>>()
                .map_err(|_e| Error::MessageParseError)?
                .expect("record expected");
            target
                .push(rr)
                .map_err(|_e| Error::MessageBuilderPushError)?;
        }

        let mut source = source
            .next_section()
            .map_err(|_e| Error::MessageParseError)?
            .expect("section should be present");
        let mut target = target.authority();
        for rr in &mut source {
            let rr = rr.map_err(|_e| Error::MessageParseError)?;
            let rr = rr
                .into_record::<AllRecordData<_, ParsedDname<_>>>()
                .map_err(|_e| Error::MessageParseError)?
                .expect("record expected");
            target
                .push(rr)
                .map_err(|_e| Error::MessageBuilderPushError)?;
        }

        let source = source
            .next_section()
            .map_err(|_e| Error::MessageParseError)?
            .expect("section should be present");
        let mut target = target.additional();
        for rr in source {
            let rr = rr.map_err(|_e| Error::MessageParseError)?;
            if rr.rtype() == Rtype::Opt {
            } else {
                let rr = rr
                    .into_record::<AllRecordData<_, ParsedDname<_>>>()
                    .map_err(|_e| Error::MessageParseError)?
                    .expect("record expected");
                target
                    .push(rr)
                    .map_err(|_e| Error::MessageBuilderPushError)?;
            }
        }

        if self.udp_payload_size.is_some() || !self.opts.is_empty() {
            target
                .opt(|opt| {
                    if let Some(size) = self.udp_payload_size {
                        opt.set_udp_payload_size(size)
                    }
                    for o in &self.opts {
                        match o {
                            OptTypes::TypeTcpKeepalive(tka) => {
                                opt.tcp_keepalive(tka.timeout())?
                            }
                        }
                    }
                    Ok(())
                })
                .map_err(|_e| Error::MessageBuilderPushError)?;
        }

        // It would be nice to use .builder() here. But that one deletes all
        // section. We have to resort to .as_builder() which gives a
        // reference and then .clone()
        let result = target.as_builder().clone();
        let msg = Message::from_octets(result.finish().into_target()).expect(
            "Message should be able to parse output from MessageBuilder",
        );
        Ok(msg)
    }
}

impl<Octs: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + 'static>
    ComposeRequest for RequestMessage<Octs>
{
    fn as_box_dyn(&self) -> Box<dyn ComposeRequest> {
        Box::new(self.clone())
    }

    fn to_vec(&self) -> Vec<u8> {
        let msg = self.to_message();
        msg.as_octets().clone()
    }

    fn to_message(&self) -> Message<Vec<u8>> {
        self.to_message_impl().unwrap()
    }

    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    fn set_udp_payload_size(&mut self, value: u16) {
        self.udp_payload_size = Some(value);
    }

    fn add_opt(&mut self, opt: OptTypes) {
        self.opts.push(opt);
        //println!("add_opt: after push: {:?}", self);
    }
}
