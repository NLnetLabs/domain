//! Constructing and sending requests.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::base::iana::Rcode;
use crate::base::message::CopyRecordsError;
use crate::base::message_builder::{
    AdditionalBuilder, MessageBuilder, PushError, StaticCompressor,
};
use crate::base::opt::{ComposeOptData, LongOptData, OptRecord};
use crate::base::wire::Composer;
use crate::base::{Header, Message, ParsedDname, Rtype};
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
    /// Appends the final message to a provided composer.
    fn append_message<Target: Composer>(
        &self,
        target: &mut Target,
    ) -> Result<(), CopyRecordsError>;

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

    /// Returns whether a message is an answer to the request.
    fn is_answer(&self, answer: &Message<[u8]>) -> bool;
}

//------------ SendRequest ---------------------------------------------------

/// Trait for starting a DNS request based on a request composer.
///
/// In the future, the return type of request should become an associated type.
/// However, the use of 'dyn Request' in redundant currently prevents that.
pub trait SendRequest<CR> {
    /// Request function that takes a ComposeRequest type.
    fn send_request(&self, request_msg: CR) -> Box<dyn GetResponse + Send>;
}

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

    /// Appends the message to a composer.
    fn append_message_impl<Target: Composer>(
        &self,
        mut target: MessageBuilder<Target>,
    ) -> Result<AdditionalBuilder<Target>, CopyRecordsError> {
        let source = &self.msg;

        *target.header_mut() = self.header;

        let source = source.question();
        let mut target = target.question();
        for rr in source {
            target.push(rr?)?;
        }
        let mut source = source.answer()?;
        let mut target = target.answer();
        for rr in &mut source {
            let rr = rr?
                .into_record::<AllRecordData<_, ParsedDname<_>>>()?
                .expect("record expected");
            target.push(rr)?;
        }

        let mut source =
            source.next_section()?.expect("section should be present");
        let mut target = target.authority();
        for rr in &mut source {
            let rr = rr?
                .into_record::<AllRecordData<_, ParsedDname<_>>>()?
                .expect("record expected");
            target.push(rr)?;
        }

        let source =
            source.next_section()?.expect("section should be present");
        let mut target = target.additional();
        for rr in source {
            let rr = rr?;
            if rr.rtype() != Rtype::Opt {
                let rr = rr
                    .into_record::<AllRecordData<_, ParsedDname<_>>>()?
                    .expect("record expected");
                target.push(rr)?;
            }
        }

        if let Some(opt) = self.opt.as_ref() {
            target.push(opt.as_record())?;
        }

        Ok(target)
    }

    /// Create new message based on the changes to the base message.
    fn to_message_impl(&self) -> Result<Message<Vec<u8>>, Error> {
        let target =
            MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
                .expect("Vec is expected to have enough space");

        let target = self.append_message_impl(target)?;

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
    fn append_message<Target: Composer>(
        &self,
        target: &mut Target,
    ) -> Result<(), CopyRecordsError> {
        let target = MessageBuilder::from_target(target)
            .map_err(|_| CopyRecordsError::Push(PushError::ShortBuf))?;
        self.append_message_impl(target)?;
        Ok(())
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
        self.opt_mut().set_udp_payload_size(value);
    }

    fn add_opt(
        &mut self,
        opt: &impl ComposeOptData,
    ) -> Result<(), LongOptData> {
        self.opt_mut().push(opt).map_err(|e| e.unlimited_buf())
    }

    fn is_answer(&self, answer: &Message<[u8]>) -> bool {
        let answer_header = answer.header();
        let answer_hcounts = answer.header_counts();

        // First check qr is set and IDs match.
        if !answer_header.qr() || answer_header.id() != self.header.id() {
            return false;
        }

        // If the result is an error, then the question section can be empty.
        // In that case we require all other sections to be empty as well.
        if answer_header.rcode() != Rcode::NoError
            && answer_hcounts.qdcount() == 0
            && answer_hcounts.ancount() == 0
            && answer_hcounts.nscount() == 0
            && answer_hcounts.arcount() == 0
        {
            // We can accept this as a valid reply.
            return true;
        }

        // Now the question section in the reply has to be the same as in the
        // query.
        if answer_hcounts.qdcount() != self.msg.header_counts().qdcount() {
            false
        } else {
            answer.question() == self.msg.for_slice().question()
        }
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

    /// Underlying transport not found in redundant connection
    RedundantTransportNotFound,

    /// Octet sequence too short to be a valid DNS message.
    ShortMessage,

    /// Message too long for stream transport.
    StreamLongMessage,

    /// Stream transport closed because it was idle (for too long).
    StreamIdleTimeout,

    /// Error receiving a reply.
    //
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

    /// Reply does not match the query.
    WrongReplyForQuery,

    /// No transport available to transmit request.
    NoTransportAvailable,

    /// An error happened in the datagram transport.
    Dgram(Arc<super::dgram::QueryError>),
}

impl From<LongOptData> for Error {
    fn from(_: LongOptData) -> Self {
        Self::OptTooLong
    }
}

impl From<super::dgram::QueryError> for Error {
    fn from(err: super::dgram::QueryError) -> Self {
        Self::Dgram(err.into())
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
            Error::RedundantTransportNotFound => write!(
                f,
                "Underlying transport not found in redundant connection"
            ),
            Error::ShortMessage => {
                write!(f, "octet sequence to short to be a valid message")
            }
            Error::StreamLongMessage => {
                write!(f, "message too long for stream transport")
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
            Error::WrongReplyForQuery => {
                write!(f, "reply does not match query")
            }
            Error::NoTransportAvailable => {
                write!(f, "no transport available")
            }
            Error::Dgram(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl From<CopyRecordsError> for Error {
    fn from(err: CopyRecordsError) -> Self {
        match err {
            CopyRecordsError::Parse(_) => Self::MessageParseError,
            CopyRecordsError::Push(_) => Self::MessageBuilderPushError,
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
            Error::RedundantTransportNotFound => None,
            Error::ShortMessage => None,
            Error::StreamLongMessage => None,
            Error::StreamIdleTimeout => None,
            Error::StreamReceiveError => None,
            Error::StreamReadError(e) => Some(e),
            Error::StreamReadTimeout => None,
            Error::StreamTooManyOutstandingQueries => None,
            Error::StreamWriteError(e) => Some(e),
            Error::StreamUnexpectedEndOfData => None,
            Error::WrongReplyForQuery => None,
            Error::NoTransportAvailable => None,
            Error::Dgram(err) => Some(err),
        }
    }
}
