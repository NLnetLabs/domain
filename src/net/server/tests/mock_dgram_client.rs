//! A client for testing over datagram protocols.
//!
//! Based on net::client::dgram but intended for use by Stelline tests that
//! require complete control over the client request. This client does NOT
//! for example add EDNS OPT records or apply DNS name compression to queries
//! that it is asked to send, nor does it time out or retry (as it is assumed
//! that a mock network connection will be used).

#![warn(missing_docs)]

use core::fmt;

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
//use std::prelude::v1::Vec;
use std::sync::Arc;

use bytes::Bytes;
use octseq::OctetsInto;
use tracing::trace;

use crate::base::Message;
use crate::net::client::protocol::{
    AsyncConnect, AsyncDgramRecv, AsyncDgramRecvEx, AsyncDgramSend,
    AsyncDgramSendEx,
};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};

//------------ Configuration Constants ----------------------------------------

/// The default receive buffer size.
const DEF_RECV_SIZE: usize = 2000;

//------------ Config ---------------------------------------------------------

/// Configuration of a datagram transport.
#[derive(Clone, Debug)]
pub struct Config {
    /// Receive buffer size.
    recv_size: usize,
}

impl Config {
    /// Creates a new config with default values.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the receive buffer size.
    ///
    /// This is the amount of memory that is allocated for receiving a
    /// response.
    #[allow(dead_code)]
    pub fn set_recv_size(&mut self, size: usize) {
        self.recv_size = size
    }

    /// Returns the receive buffer size.
    #[allow(dead_code)]
    pub fn recv_size(&self) -> usize {
        self.recv_size
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            recv_size: DEF_RECV_SIZE,
        }
    }
}

//------------ Connection -----------------------------------------------------

/// A datagram protocol connection.
#[derive(Clone, Debug)]
pub struct Connection<S> {
    /// Actual state of the connection.
    state: Arc<ConnectionState<S>>,
}

/// Because it owns the connection’s resources, this type is not [`Clone`].
/// However, it is entirely safe to share it by sticking it into e.g. an arc.
#[derive(Debug)]
struct ConnectionState<S> {
    /// User configuration variables.
    config: Config,

    /// Connections to datagram sockets.
    connect: S,
}

impl<S> Connection<S> {
    /// Create a new datagram transport with default configuration.
    pub fn new(connect: S) -> Self {
        Self::with_config(connect, Default::default())
    }

    /// Create a new datagram transport with a given configuration.
    pub fn with_config(connect: S, config: Config) -> Self {
        Self {
            state: Arc::new(ConnectionState { config, connect }),
        }
    }
}

impl<S> Connection<S>
where
    S: AsyncConnect,
    S::Connection: AsyncDgramRecv + AsyncDgramSend + Unpin,
{
    /// Performs a request.
    ///
    /// Sends the provided and returns either a response or an error.
    async fn handle_request_impl<Req: ComposeRequest>(
        self,
        mut request: Req,
    ) -> Result<Message<Bytes>, Error> {
        // A place to store the receive buffer for reuse.
        let mut reuse_buf = None;

        let mut sock = self
            .state
            .connect
            .connect()
            .await
            .map_err(|_| Error::ConnectionClosed)?;

        // Set predictable ID in header.
        request.header_mut().set_id(0);

        // Create the message and send it out.
        let request_msg = request.to_message().expect(
            "Message should be able to parse output from MessageBuilder",
        );

        let dgram = request_msg.as_slice();
        let sent = sock
            .send(dgram)
            .await
            .map_err(|err| Error::StreamWriteError(Arc::new(err)))?;
        if sent != dgram.len() {
            return Err(Error::ShortMessage);
        }

        let mut buf = reuse_buf.take().unwrap_or_else(|| {
            // XXX use uninit'ed mem here.
            vec![0; self.state.config.recv_size]
        });
        let len = sock
            .recv(&mut buf)
            .await
            .map_err(|err| Error::StreamReadError(Arc::new(err)))?;

        trace!("Received {len} bytes of message");
        buf.truncate(len);

        let answer = Message::try_from_octets(buf)
            .expect("Response could not be parsed");

        trace!("Received message is accepted");
        Ok(answer.octets_into())
    }
}

//--- SendRequest

impl<S, Req> SendRequest<Req> for Connection<S>
where
    S: AsyncConnect + Clone + Send + Sync + 'static,
    S::Connection:
        AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
    Req: ComposeRequest + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: Req,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request {
            fut: Box::pin(self.clone().handle_request_impl(request_msg)),
        })
    }
}

//------------ Request ------------------------------------------------------

/// The state of a DNS request.
pub struct Request {
    /// Future that does the actual work of GetResponse.
    fut: Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + Sync>,
    >,
}

impl Request {
    /// Async function that waits for the future stored in Request to complete.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        (&mut self.fut).await
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        todo!()
    }
}

impl GetResponse for Request {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Message<Bytes>, Error>>
                + Send
                + Sync
                + '_,
        >,
    > {
        Box::pin(self.get_response_impl())
    }
}
