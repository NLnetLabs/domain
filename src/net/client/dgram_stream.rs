//! A UDP transport that falls back to TCP if the reply is truncated

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - handle shutdown

use crate::base::Message;
use crate::net::client::dgram;
use crate::net::client::multi_stream;
use crate::net::client::protocol::{
    AsyncConnect, AsyncDgramRecv, AsyncDgramSend,
};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, HandleRequest, SendRequest,
};
use bytes::Bytes;
use futures_util::FutureExt;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

//------------ Config ---------------------------------------------------------

/// Configuration for an octet_stream transport connection.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Configuration for the UDP transport.
    dgram: dgram::Config,

    /// Configuration for the multi_stream (TCP) transport.
    multi_stream: multi_stream::Config,
}

impl Config {
    /// Creates a new config with default values.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a new config from the two portions.
    pub fn from_parts(
        dgram: dgram::Config,
        multi_stream: multi_stream::Config,
    ) -> Self {
        Self {
            dgram,
            multi_stream,
        }
    }

    /// Returns the datagram config.
    pub fn dgram(&self) -> &dgram::Config {
        &self.dgram
    }

    /// Returns a mutable reference to the datagram config.
    pub fn dgram_mut(&mut self) -> &mut dgram::Config {
        &mut self.dgram
    }

    /// Sets the datagram config.
    pub fn set_dgram(&mut self, dgram: dgram::Config) {
        self.dgram = dgram
    }

    /// Returns the stream config.
    pub fn stream(&self) -> &multi_stream::Config {
        &self.multi_stream
    }

    /// Returns a mutable reference to the stream config.
    pub fn stream_mut(&mut self) -> &mut multi_stream::Config {
        &mut self.multi_stream
    }

    /// Sets the stream config.
    pub fn set_stream(&mut self, stream: multi_stream::Config) {
        self.multi_stream = stream
    }
}

//------------ Connection -----------------------------------------------------

/// DNS transport connection that first issues a query over a UDP transport and
/// falls back to TCP if the reply is truncated.
#[derive(Clone)]
pub struct Connection<DgramS, Req> {
    /// The UDP transport connection.
    udp_conn: Arc<dgram::Connection<DgramS>>,

    /// The TCP transport connection.
    tcp_conn: multi_stream::Connection<Req>,
}

impl<DgramS, Req> Connection<DgramS, Req>
where
    DgramS: AsyncConnect + Clone + Send + Sync + 'static,
    DgramS::Connection:
        AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
{
    /// Creates a new multi-stream transport with default configuration.
    pub fn new<StreamS>(
        dgram_remote: DgramS,
        stream_remote: StreamS,
    ) -> (Self, multi_stream::Transport<StreamS, Req>) {
        Self::with_config(dgram_remote, stream_remote, Default::default())
    }

    /// Creates a new multi-stream transport.
    pub fn with_config<StreamS>(
        dgram_remote: DgramS,
        stream_remote: StreamS,
        config: Config,
    ) -> (Self, multi_stream::Transport<StreamS, Req>) {
        let udp_conn =
            dgram::Connection::new(Some(config.dgram), dgram_remote).into();
        let (tcp_conn, transport) = multi_stream::Connection::with_config(
            stream_remote,
            config.multi_stream,
        );
        (Self { udp_conn, tcp_conn }, transport)
    }
}

impl<DgramS, Req> Connection<DgramS, Req>
where
    DgramS: AsyncConnect,
    DgramS::Connection: AsyncDgramRecv + AsyncDgramSend + Unpin,
    Req: ComposeRequest + Clone,
{
    /// Sends a request and receives a response.
    pub async fn request(
        &self,
        request: Req,
    ) -> Result<Message<Bytes>, Error> {
        let response = self.udp_conn.request(request.clone()).await?;
        if !response.header().tc() {
            return Ok(response);
        }
        self.tcp_conn.request(request).await
    }
}

impl<DgramS, Req> Connection<DgramS, Req>
where
    DgramS: AsyncConnect + Clone + Debug + Send + Sync + 'static,
    DgramS::Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin,
    Req: ComposeRequest + Clone + 'static,
{
    /// Start a request for the Request trait.
    async fn request_impl(
        &self,
        request_msg: &Req,
    ) -> Result<Box<dyn GetResponse + Send>, Error> {
        Ok(Box::new(Query::new(
            request_msg,
            self.udp_conn.clone(),
            self.tcp_conn.clone(),
        )))
    }
}

//--- SendRequest and HandleRequest

impl<DgramS, Req> SendRequest<Req> for Connection<DgramS, Req>
where
    DgramS: AsyncConnect + Clone + Debug + Send + Sync + 'static,
    DgramS::Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin,
    Req: ComposeRequest + Clone + 'static,
{
    fn send_request<'a>(
        &'a self,
        request_msg: &'a Req,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn GetResponse + Send>, Error>>
                + Send
                + '_,
        >,
    > {
        return Box::pin(self.request_impl(request_msg));
    }
}

impl<DgramS, Req> HandleRequest<Req> for Connection<DgramS, Req>
where
    DgramS: AsyncConnect + Clone + Debug + Send + Sync + 'static,
    DgramS::Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin,
    Req: ComposeRequest + Clone + 'static,
{
    type Response = Message<Bytes>;
    type Error = Error;
    type Fut<'s> = Pin<Box<
        dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 's
    >> where Self: 's;

    fn handle_request(&self, request: Req) -> Self::Fut<'_> {
        self.request(request).boxed()
    }
}

//------------ Query --------------------------------------------------------

/// Object that contains the current state of a query.
#[derive(Debug)]
pub struct Query<S, Req> {
    /// Reqeust message.
    request_msg: Req,

    /// UDP transport to be used.
    udp_conn: Arc<dgram::Connection<S>>,

    /// TCP transport to be used.
    tcp_conn: multi_stream::Connection<Req>,

    /// Current state of the request.
    state: QueryState,
}

/// Status of the query.
#[derive(Debug)]
enum QueryState {
    /// Start a request over the UDP transport.
    StartUdpRequest,

    /// Get the response from the UDP transport.
    GetUdpResponse(Box<dyn GetResponse + Send>),

    /// Start a request over the TCP transport.
    StartTcpRequest,

    /// Get the response from the TCP transport.
    GetTcpResponse(Box<dyn GetResponse + Send>),
}

impl<S, Req> Query<S, Req>
where
    S: AsyncConnect + Clone + Send + Sync + 'static,
    Req: ComposeRequest + Clone + 'static,
{
    /// Create a new Query object.
    ///
    /// The initial state is to start with a UDP transport.
    fn new(
        request_msg: &Req,
        udp_conn: Arc<dgram::Connection<S>>,
        tcp_conn: multi_stream::Connection<Req>,
    ) -> Query<S, Req> {
        Self {
            request_msg: request_msg.clone(),
            udp_conn,
            tcp_conn,
            state: QueryState::StartUdpRequest,
        }
    }

    /// Get the response of a DNS request.
    ///
    /// This function is cancel safe.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error>
    where
        S::Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin,
    {
        loop {
            match &mut self.state {
                QueryState::StartUdpRequest => {
                    let msg = self.request_msg.clone();
                    let request = self.udp_conn.send_request(&msg).await?;
                    self.state = QueryState::GetUdpResponse(request);
                    continue;
                }
                QueryState::GetUdpResponse(ref mut request) => {
                    let response = request.get_response().await?;
                    if response.header().tc() {
                        self.state = QueryState::StartTcpRequest;
                        continue;
                    }
                    return Ok(response);
                }
                QueryState::StartTcpRequest => {
                    let msg = self.request_msg.clone();
                    let request = self.tcp_conn.send_request(&msg).await?;
                    self.state = QueryState::GetTcpResponse(request);
                    continue;
                }
                QueryState::GetTcpResponse(ref mut query) => {
                    let response = query.get_response().await?;
                    return Ok(response);
                }
            }
        }
    }
}

impl<S, Req> GetResponse for Query<S, Req>
where
    S: AsyncConnect + Clone + Debug + Send + Sync + 'static,
    S::Connection: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin,
    Req: ComposeRequest + Clone + 'static,
{
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_response_impl())
    }
}
