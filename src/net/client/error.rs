//! Error type for client transports.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

/// Error type for client transports.
#[derive(Clone, Debug)]
pub enum Error {
    /// Connection was already closed.
    ConnectionClosed,

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

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Error::ConnectionClosed => write!(f, "connection closed"),
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
