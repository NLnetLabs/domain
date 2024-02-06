//------------ MsgProvider ---------------------------------------------------

use crate::base::{message::ShortMessage, Message};

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

/// An implementation of MsgProvider for DNS [`Message`]s.
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

    #[must_use]
    fn determine_msg_len(hdr_buf: &mut RequestOctets) -> usize {
        u16::from_be_bytes(hdr_buf.as_ref().try_into().unwrap()) as usize
    }

    fn from_octets(octets: RequestOctets) -> Result<Self, ShortMessage> {
        Self::from_octets(octets)
    }
}

//------------ ContextAwareMessage -------------------------------------------

pub struct ContextAwareMessage<T> {
    message: T,
    received_over_tcp: bool,
    client_addr: std::net::SocketAddr,
}

impl<T> ContextAwareMessage<T> {
    pub fn new(
        message: T,
        received_over_tcp: bool,
        client_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            message,
            received_over_tcp,
            client_addr,
        }
    }

    pub fn received_over_tcp(&self) -> bool {
        self.received_over_tcp
    }

    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    pub fn into_inner(self) -> T {
        self.message
    }
}

impl<T> core::ops::Deref for ContextAwareMessage<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl<T> core::ops::DerefMut for ContextAwareMessage<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}
