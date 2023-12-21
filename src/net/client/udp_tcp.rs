//! A UDP transport that falls back to TCP if the reply is truncated

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - handle shutdown

use bytes::Bytes;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use crate::base::Message;
use crate::net::client::compose_request::ComposeRequest;
use crate::net::client::error::Error;
use crate::net::client::multi_stream;
use crate::net::client::protocol::TcpConnect;
use crate::net::client::request::{GetResponse, Request};
use crate::net::client::udp;

//------------ Config ---------------------------------------------------------

/// Configuration for an octet_stream transport connection.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Configuration for the UDP transport.
    pub udp: Option<udp::Config>,

    /// Configuration for the multi_stream (TCP) transport.
    pub multi_stream: Option<multi_stream::Config>,
}

//------------ Connection -----------------------------------------------------

/// DNS transport connection that first issues a query over a UDP transport and
/// falls back to TCP if the reply is truncated.
#[derive(Clone)]
pub struct Connection<BMB> {
    /// Reference to the real object that provides the connection.
    inner: Arc<InnerConnection<BMB>>,
}

impl<CR: ComposeRequest + Clone + 'static> Connection<CR> {
    /// Create a new connection.
    pub fn new(
        config: Option<Config>,
        remote_addr: SocketAddr,
    ) -> Result<Self, Error> {
        let config = match config {
            Some(config) => {
                check_config(&config)?;
                config
            }
            None => Default::default(),
        };
        let connection = InnerConnection::new(config, remote_addr)?;
        Ok(Self {
            inner: Arc::new(connection),
        })
    }

    /// Worker function for a connection object.
    pub fn run(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> {
        self.inner.run()
    }

    /// Start a request for the Request trait.
    async fn request_impl(
        &self,
        request_msg: &CR,
    ) -> Result<Box<dyn GetResponse + Send>, Error> {
        let gr = self.inner.request(request_msg).await?;
        Ok(Box::new(gr))
    }
}

impl<CR: ComposeRequest + Clone + 'static> Request<CR> for Connection<CR> {
    fn request<'a>(
        &'a self,
        request_msg: &'a CR,
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

//------------ ReqResp --------------------------------------------------------

/// Object that contains the current state of a query.
#[derive(Debug)]
pub struct ReqResp<BMB> {
    /// Reqeust message.
    request_msg: BMB,

    /// UDP transport to be used.
    udp_conn: udp::Connection,

    /// TCP transport to be used.
    tcp_conn: multi_stream::Connection<BMB>,

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

impl<CR: ComposeRequest + Clone + 'static> ReqResp<CR> {
    /// Create a new ReqResp object.
    ///
    /// The initial state is to start with a UDP transport.
    fn new(
        request_msg: &CR,
        udp_conn: udp::Connection,
        tcp_conn: multi_stream::Connection<CR>,
    ) -> ReqResp<CR> {
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
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        loop {
            match &mut self.state {
                QueryState::StartUdpRequest => {
                    let msg = self.request_msg.clone();
                    let request = self.udp_conn.request(&msg).await?;
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
                    let request = self.tcp_conn.request(&msg).await?;
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

impl<CR: ComposeRequest + Clone + Debug + 'static> GetResponse
    for ReqResp<CR>
{
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ InnerConnection ------------------------------------------------

/// The actual connection object.
struct InnerConnection<BMB> {
    /// The remote address to connect to.
    remote_addr: SocketAddr,

    /// The UDP transport connection.
    udp_conn: udp::Connection,

    /// The TCP transport connection.
    tcp_conn: multi_stream::Connection<BMB>,
}

impl<CR: ComposeRequest + Clone + 'static> InnerConnection<CR> {
    /// Create a new InnerConnection object.
    ///
    /// Create the UDP and TCP connections. Store the remote address because
    /// run needs it later.
    fn new(config: Config, remote_addr: SocketAddr) -> Result<Self, Error> {
        let udp_conn = udp::Connection::new(config.udp, remote_addr)?;
        let tcp_conn = multi_stream::Connection::new(config.multi_stream)?;

        Ok(Self {
            remote_addr,
            udp_conn,
            tcp_conn,
        })
    }

    /// Implementation of the worker function.
    ///
    /// Create a TCP connect object and pass that to run function
    /// of the multi_stream object.
    fn run(&self) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> {
        let tcp_connect = TcpConnect::new(self.remote_addr);

        let fut = self.tcp_conn.run(tcp_connect);
        Box::pin(fut)
    }

    /// Implementation of the request function.
    ///
    /// Just create a ReqResp object with the state it needs.
    async fn request(&self, request_msg: &CR) -> Result<ReqResp<CR>, Error> {
        Ok(ReqResp::new(
            request_msg,
            self.udp_conn.clone(),
            self.tcp_conn.clone(),
        ))
    }
}

/// Check if config is valid.
fn check_config(_config: &Config) -> Result<(), Error> {
    // Nothing to check at the moment.
    Ok(())
}
