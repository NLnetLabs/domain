//! Requests.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::base::opt::{ComposeOptData, LongOptData, OptRecord};
use crate::base::{
    Header, Message, MessageBuilder, ParsedDname, Rtype, StaticCompressor,
};
use crate::rdata::AllRecordData;
use bytes::Bytes;
use octseq::Octets;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;
use std::{error, fmt};

//------------ ComposeRequest ------------------------------------------------

/// A trait that allows composing a request as a series.
pub trait ComposeRequest: Debug + Send + Sync {
    /// Create a message that captures the recorded changes.
    fn to_message(&self) -> Message<Vec<u8>>;

    /// Create a message that captures the recorded changes and convert to
    /// a Vec.
    fn to_vec(&self) -> Vec<u8>;

    /// Return a reference to a mutable Header to record changes to the header.
    fn header_mut(&mut self) -> &mut Header;

    /// Set the UDP payload size.
    fn set_udp_payload_size(&mut self, value: u16);

    /// Add an EDNS option.
    fn add_opt(
        &mut self,
        opt: &impl ComposeOptData,
    ) -> Result<(), LongOptData>;
}

//------------ Request -------------------------------------------------------

/// Trait for starting a DNS request based on a request composer.
///
/// In the future, the return type of request should become an associated type.
/// However, the use of 'dyn Request' in redundant currently prevents that.
pub trait SendRequest<CR> {
    /// Request function that takes a ComposeRequest type.
    ///
    /// This function is intended to be cancel safe.
    fn send_request<'a>(
        &'a self,
        request_msg: &'a CR,
    ) -> Pin<Box<dyn Future<Output = RequestResultOutput> + Send + '_>>;
}

/// This type is the actual result type of the future returned by the
/// request function in the Request trait.
type RequestResultOutput = Result<Box<dyn GetResponse + Send>, Error>;

//------------ GetResponse ---------------------------------------------------

/// Trait for getting the result of a DNS query.
///
/// In the future, the return type of get_response should become an associated
/// type. However, too many uses of 'dyn GetResponse' currently prevent that.
pub trait GetResponse: Debug {
    /// Get the result of a DNS request.
    ///
    /// This function is intended to be cancel safe.
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    >;
}

//------------ RequestMessage ------------------------------------------------

/// Object that implements the ComposeRequest trait for a Message object.
#[derive(Clone, Debug)]
pub struct RequestMessage<Octs: AsRef<[u8]>> {
    /// Base message.
    msg: Message<Octs>,

    /// New header.
    header: Header,

    /// The OPT record to add if required.
    opt: Option<OptRecord<Vec<u8>>>,
}

impl<Octs: AsRef<[u8]> + Debug + Octets> RequestMessage<Octs> {
    /// Create a new BMB object.
    pub fn new(msg: impl Into<Message<Octs>>) -> Self {
        let msg = msg.into();
        let header = msg.header();
        Self {
            msg,
            header,
            opt: None,
        }
    }

    /// Returns a mutable reference to the OPT record.
    ///
    /// Adds one if necessary.
    fn opt_mut(&mut self) -> &mut OptRecord<Vec<u8>> {
        self.opt.get_or_insert_with(Default::default)
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

        if let Some(opt) = self.opt.as_ref() {
            target
                .push(opt.as_record())
                .map_err(|_| Error::MessageBuilderPushError)?;
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
        self.opt_mut().set_udp_payload_size(value);
    }

    fn add_opt(
        &mut self,
        opt: &impl ComposeOptData,
    ) -> Result<(), LongOptData> {
        self.opt_mut().push(opt).map_err(|e| e.unlimited_buf())
    }
}

//------------ Error ---------------------------------------------------------

/// Error type for client transports.
#[derive(Clone, Debug)]
pub enum Error {
    /// Connection was already closed.
    ConnectionClosed,

    /// The OPT record has become too long.
    OptTooLong,

    /// PushError from MessageBuilder.
    MessageBuilderPushError,

    /// ParseError from Message.
    MessageParseError,

    /// octet_stream configuration error.
    OctetStreamConfigError(Arc<std::io::Error>),

    /// Underlying transport not found in redundant connection
    RedundantTransportNotFound,

    /// Octet sequence too short to be a valid DNS message.
    ShortMessage,

    /// Stream transport closed because it was idle (for too long).
    StreamIdleTimeout,

    /// Error receiving a reply.
    StreamReceiveError,

    /// Reading from stream gave an error.
    StreamReadError(Arc<std::io::Error>),

    /// Reading from stream took too long.
    StreamReadTimeout,

    /// Too many outstand queries on a single stream transport.
    StreamTooManyOutstandingQueries,

    /// Writing to a stream gave an error.
    StreamWriteError(Arc<std::io::Error>),

    /// Reading for a stream ended unexpectedly.
    StreamUnexpectedEndOfData,

    /// Binding a UDP socket gave an error.
    UdpBind(Arc<std::io::Error>),

    /// UDP configuration error.
    UdpConfigError(Arc<std::io::Error>),

    /// Connecting a UDP socket gave an error.
    UdpConnect(Arc<std::io::Error>),

    /// Receiving from a UDP socket gave an error.
    UdpReceive(Arc<std::io::Error>),

    /// Sending over a UDP socket gaven an error.
    UdpSend(Arc<std::io::Error>),

    /// Sending over a UDP socket gave a partial result.
    UdpShortSend,

    /// Timeout receiving a response over a UDP socket.
    UdpTimeoutNoResponse,

    /// Reply does not match the query.
    WrongReplyForQuery,

    /// No transport available to transmit request.
    NoTransportAvailable,
}

impl From<LongOptData> for Error {
    fn from(_: LongOptData) -> Self {
        Self::OptTooLong
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ConnectionClosed => write!(f, "connection closed"),
            Error::OptTooLong => write!(f, "OPT record is too long"),
            Error::MessageBuilderPushError => {
                write!(f, "PushError from MessageBuilder")
            }
            Error::MessageParseError => write!(f, "ParseError from Message"),
            Error::OctetStreamConfigError(_) => write!(f, "bad config value"),
            Error::RedundantTransportNotFound => write!(
                f,
                "Underlying transport not found in redundant connection"
            ),
            Error::ShortMessage => {
                write!(f, "octet sequence to short to be a valid message")
            }
            Error::StreamIdleTimeout => {
                write!(f, "stream was idle for too long")
            }
            Error::StreamReceiveError => write!(f, "error receiving a reply"),
            Error::StreamReadError(_) => {
                write!(f, "error reading from stream")
            }
            Error::StreamReadTimeout => {
                write!(f, "timeout reading from stream")
            }
            Error::StreamTooManyOutstandingQueries => {
                write!(f, "too many outstanding queries on stream")
            }
            Error::StreamWriteError(_) => {
                write!(f, "error writing to stream")
            }
            Error::StreamUnexpectedEndOfData => {
                write!(f, "unexpected end of data")
            }
            Error::UdpBind(_) => write!(f, "error binding UDP socket"),
            Error::UdpConfigError(_) => write!(f, "bad config value"),
            Error::UdpConnect(_) => write!(f, "error connecting UDP socket"),
            Error::UdpReceive(_) => {
                write!(f, "error receiving from UDP socket")
            }
            Error::UdpSend(_) => write!(f, "error sending to UDP socket"),
            Error::UdpShortSend => write!(f, "partial sent to UDP socket"),
            Error::UdpTimeoutNoResponse => {
                write!(f, "timeout waiting for response")
            }
            Error::WrongReplyForQuery => {
                write!(f, "reply does not match query")
            }
            Error::NoTransportAvailable => {
                write!(f, "no transport available")
            }
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::ConnectionClosed => None,
            Error::OptTooLong => None,
            Error::MessageBuilderPushError => None,
            Error::MessageParseError => None,
            Error::OctetStreamConfigError(e) => Some(e),
            Error::RedundantTransportNotFound => None,
            Error::ShortMessage => None,
            Error::StreamIdleTimeout => None,
            Error::StreamReceiveError => None,
            Error::StreamReadError(e) => Some(e),
            Error::StreamReadTimeout => None,
            Error::StreamTooManyOutstandingQueries => None,
            Error::StreamWriteError(e) => Some(e),
            Error::StreamUnexpectedEndOfData => None,
            Error::UdpBind(e) => Some(e),
            Error::UdpConfigError(e) => Some(e),
            Error::UdpConnect(e) => Some(e),
            Error::UdpReceive(e) => Some(e),
            Error::UdpSend(e) => Some(e),
            Error::UdpShortSend => None,
            Error::UdpTimeoutNoResponse => None,
            Error::WrongReplyForQuery => None,
            Error::NoTransportAvailable => None,
        }
    }
}
