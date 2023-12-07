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
use crate::net::client::base_message_builder::BaseMessageBuilder;
use crate::net::client::error::Error;
use crate::net::client::multi_stream;
use crate::net::client::query::{GetResult, QueryMessage4};
use crate::net::client::tcp_connect::TcpConnect;
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

impl<BMB: BaseMessageBuilder + Clone + 'static> Connection<BMB> {
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

    /// Start a query for the QueryMessage4 trait.
    async fn query_impl4(
        &self,
        query_msg: &BMB,
    ) -> Result<Box<dyn GetResult + Send>, Error> {
        let gr = self.inner.query(query_msg).await?;
        Ok(Box::new(gr))
    }
}

impl<BMB: BaseMessageBuilder + Clone + 'static> QueryMessage4<BMB>
    for Connection<BMB>
{
    fn query<'a>(
        &'a self,
        query_msg: &'a BMB,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn GetResult + Send>, Error>>
                + Send
                + '_,
        >,
    > {
        return Box::pin(self.query_impl4(query_msg));
    }
}

//------------ Query ----------------------------------------------------------

/// Object that contains the current state of a query.
#[derive(Debug)]
pub struct Query<BMB> {
    /// Reqeust message.
    query_msg: BMB,

    /// UDP transport to be used.
    udp_conn: udp::Connection,

    /// TCP transport to be used.
    tcp_conn: multi_stream::Connection<BMB>,

    /// Current state of the query.
    state: QueryState,
}

/// Status of the query.
#[derive(Debug)]
enum QueryState {
    /// Start a query over the UDP transport.
    StartUdpQuery,

    /// Get the result from the UDP transport.
    GetUdpResult(Box<dyn GetResult + Send>),

    /// Start a query over the TCP transport.
    StartTcpQuery,

    /// Get the result from the TCP transport.
    GetTcpResult(Box<dyn GetResult + Send>),
}

impl<BMB: BaseMessageBuilder + Clone + 'static> Query<BMB> {
    /// Create a new Query object.
    ///
    /// The initial state is to start with a UDP transport.
    fn new(
        query_msg: &BMB,
        udp_conn: udp::Connection,
        tcp_conn: multi_stream::Connection<BMB>,
    ) -> Query<BMB> {
        Query {
            query_msg: query_msg.clone(),
            udp_conn,
            tcp_conn,
            state: QueryState::StartUdpQuery,
        }
    }

    /// Get the result of a DNS query.
    ///
    /// This function is cancel safe.
    async fn get_result_impl(&mut self) -> Result<Message<Bytes>, Error> {
        loop {
            match &mut self.state {
                QueryState::StartUdpQuery => {
                    let msg = self.query_msg.clone();
                    let query =
                        QueryMessage4::query(&self.udp_conn, &msg).await?;
                    self.state = QueryState::GetUdpResult(query);
                    continue;
                }
                QueryState::GetUdpResult(ref mut query) => {
                    let reply = query.get_result().await?;
                    if reply.header().tc() {
                        self.state = QueryState::StartTcpQuery;
                        continue;
                    }
                    return Ok(reply);
                }
                QueryState::StartTcpQuery => {
                    let msg = self.query_msg.clone();
                    let query =
                        QueryMessage4::query(&self.tcp_conn, &msg).await?;
                    self.state = QueryState::GetTcpResult(query);
                    continue;
                }
                QueryState::GetTcpResult(ref mut query) => {
                    let reply = query.get_result().await?;
                    return Ok(reply);
                }
            }
        }
    }
}

impl<BMB: BaseMessageBuilder + Clone + Debug + 'static> GetResult
    for Query<BMB>
{
    fn get_result(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_result_impl())
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

impl<BMB: BaseMessageBuilder + Clone + 'static> InnerConnection<BMB> {
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

    /// Implementation of the query function.
    ///
    /// Just create a Query object with the state it needs.
    async fn query(&self, query_msg: &BMB) -> Result<Query<BMB>, Error> {
        Ok(Query::new(
            query_msg,
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
