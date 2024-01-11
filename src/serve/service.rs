use std::string::String;
use std::time::Duration;

use futures::{Future, Stream};
use octseq::OctetsBuilder;

use crate::base::{message::ShortMessage, Message, StreamTarget};

//------------ MsgProvider ---------------------------------------------------

/// A MsgProvider can determine the number of bytes of message data to expect
/// and then turn those bytes into a concrete message type.
pub trait MsgProvider<RequestOctets: AsRef<[u8]>> {
    /// The number of bytes that need to be read before it is possible to
    /// determine how many more bytes of message should follow. Not all
    /// message types require this, e.g. UDP DNS message length is determined
    /// by the size of the UDP message received, while for TCP DNS messages
    /// the number of bytes to expect is determined by the first two bytes
    /// received.
    const MIN_HDR_BYTES: usize;

    /// The concrete type of message that we produce from given message
    /// bytes.
    type Msg;

    /// The actual number of message bytes to follow given at least
    /// MIN_HDR_BYTES of message header.
    fn determine_msg_len(hdr_buf: &mut RequestOctets) -> usize;

    /// Convert a sequence of bytes to a concrete message.
    fn from_octets(octets: RequestOctets) -> Result<Self::Msg, ShortMessage>;
}

/// An implementation of MsgProvider for DNS [Message]s.
impl<RequestOctets: AsRef<[u8]>> MsgProvider<RequestOctets>
    for Message<RequestOctets>
{
    /// RFC 1035 section 4.2.2 "TCP Usage" says:
    ///     "The message is prefixed with a two byte length field which gives
    ///      the message length, excluding the two byte length field.  This
    ///      length field allows the low-level processing to assemble a
    ///      complete message before beginning to parse it."
    const MIN_HDR_BYTES: usize = 2;

    type Msg = Self;

    fn determine_msg_len(hdr_buf: &mut RequestOctets) -> usize {
        u16::from_be_bytes(hdr_buf.as_ref().try_into().unwrap()) as usize
    }

    fn from_octets(octets: RequestOctets) -> Result<Self, ShortMessage> {
        Self::from_octets(octets)
    }
}

//------------ Service -------------------------------------------------------

/// A Service is responsible for generating responses to received DNS messages.
///
/// Each [`Service`] implements a single [`Self::call()`] function which takes a DNS
/// request [`Message`] and returns either a [`Transaction`] on success, or a
/// [`ServiceError`] on failure.
///
/// Responses are encapsulated inside a [`Transaction`] which is either [Single]
/// (a single response) or [Stream] (a stream of responses, e.g. for a zone
/// transfer), where each response is a [`CallResult`].
///
/// In the common case a [`CallResult`] is a DNS response message. For some
/// advanced use cases it can instead, or additionally, direct the server
/// handling the request (or a single connection it is handling) to adjust its
/// own configuration, or even to terminate the connection.
///
/// You can either implement the [`Service`] trait directly, or use the blanket
/// impl to turn any function with a compatible signature into a [`Service`]
/// implementation.
pub trait Service<
    RequestOctets: AsRef<[u8]>,
    MsgTyp: MsgProvider<RequestOctets>,
>
{
    type Error: Send + Sync + 'static;

    type ResponseOctets: OctetsBuilder
        + Send
        + Sync
        + 'static
        + std::convert::AsRef<[u8]>;

    type Single: Future<
            Output = Result<
                CallResult<Self::ResponseOctets>,
                ServiceError<Self::Error>,
            >,
        > + Send
        + 'static;

    type Stream: Stream<
            Item = Result<
                CallResult<Self::ResponseOctets>,
                ServiceError<Self::Error>,
            >,
        > + Send
        + 'static;

    #[allow(clippy::type_complexity)]
    fn call(
        &self,
        message: MsgTyp,
    ) -> Result<
        Transaction<Self::Single, Self::Stream>,
        ServiceError<Self::Error>,
    >;
}

impl<F, SrvErr, ReqOct, RespOct, MsgTyp, Sing, Strm> Service<ReqOct, MsgTyp>
    for F
where
    F: Fn(MsgTyp) -> Result<Transaction<Sing, Strm>, ServiceError<SrvErr>>,
    ReqOct: AsRef<[u8]>,
    RespOct:
        OctetsBuilder + Send + Sync + 'static + std::convert::AsRef<[u8]>,
    MsgTyp: MsgProvider<ReqOct>,
    Sing: Future<Output = Result<CallResult<RespOct>, ServiceError<SrvErr>>>
        + Send
        + 'static,
    Strm: Stream<Item = Result<CallResult<RespOct>, ServiceError<SrvErr>>>
        + Send
        + 'static,
    SrvErr: Send + Sync + 'static,
{
    type Error = SrvErr;
    type ResponseOctets = RespOct;
    type Single = Sing;
    type Stream = Strm;

    fn call(
        &self,
        message: MsgTyp,
    ) -> Result<
        Transaction<Self::Single, Self::Stream>,
        ServiceError<Self::Error>,
    > {
        (*self)(message)
    }
}

//------------ ServiceError --------------------------------------------------

#[derive(Debug)]
pub enum ServiceError<T> {
    ServiceSpecificError(T),
    ShuttingDown,
    Other(String),
}

impl<T> std::fmt::Display for ServiceError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServiceError::ServiceSpecificError(_err) => {
                write!(f, "ServiceSpecificError")
            }
            ServiceError::ShuttingDown => {
                write!(f, "ShuttingDown")
            }
            ServiceError::Other(err) => {
                write!(f, "Other({})", err)
            }
        }
    }
}

//------------ ServiceCommand ------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub enum ServiceCommand {
    CloseConnection,
    Init,
    Reconfigure { idle_timeout: Duration },
    Shutdown,
}

//------------ CallResult ----------------------------------------------------

pub struct CallResult<ResponseOctets> {
    response: Option<StreamTarget<ResponseOctets>>,
    command: Option<ServiceCommand>,
}

/// Directions to a server on how to respond to a request.
///
/// [`CallResult`] supports the following ways to handle a client request:
///
///   - Respond to the client. This is the default case.
///
///   - Respond to the client and adjust the servers handling of requests.
///     This could be required for example to honour a client request EDNS(0)
///     OPT RR that requests that the timeout from server to client be altered.
///
///   - Ignore the client request, e.g. due to policy.
///
///   - Terminate the connection with the client, e.g. due to policy or
///     or because the service is shutting down.
///
/// For reasons of policy it may be necessary to ignore certain client
/// requests without sending a response
impl<ResponseOctets> CallResult<ResponseOctets> {
    pub fn new(response: StreamTarget<ResponseOctets>) -> Self {
        Self {
            response: Some(response),
            command: None,
        }
    }

    pub fn with_feedback(
        response: StreamTarget<ResponseOctets>,
        command: ServiceCommand,
    ) -> Self {
        Self {
            response: Some(response),
            command: Some(command),
        }
    }

    pub fn per_policy(
        command: ServiceCommand,
        response: Option<StreamTarget<ResponseOctets>>,
    ) -> Self {
        Self {
            response,
            command: Some(command),
        }
    }

    pub fn response(&mut self) -> Option<StreamTarget<ResponseOctets>> {
        self.response.take()
    }

    pub fn command(&mut self) -> Option<ServiceCommand> {
        self.command.take()
    }
}

//------------ Transaction ---------------------------------------------------

/// A server transaction generating the responses for a request.
pub enum Transaction<SingleFut, StreamFut>
where
    SingleFut: Future,
    StreamFut: Stream,
{
    /// The transaction will be concluded with a single response.
    Single(SingleFut),

    /// The transaction will results in stream of multiple responses.
    Stream(StreamFut),
}
