//! A UDP transport that falls back to TCP if the reply is truncated

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - handle shutdown

use bytes::Bytes;
use octseq::OctetsBuilder;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::base::wire::Composer;
use crate::base::{Message, MessageBuilder, StaticCompressor, StreamTarget};
use crate::net::client::multi_stream;
use crate::net::client::tcp_factory::TcpConnFactory;
use crate::net::client::udp;

/// DNS transport connection that first issue a query over a UDP transport and
/// falls back to TCP if the reply is truncated.
#[derive(Clone)]
pub struct Connection<Octs: Debug + OctetsBuilder> {
    /// Reference to the real object that provides the connection.
    inner: Arc<InnerConnection<Octs>>,
}

impl<Octs: Clone + Composer + Debug + OctetsBuilder + Send + 'static>
    Connection<Octs>
{
    /// Create a new connection.
    pub fn new(remote_addr: SocketAddr) -> io::Result<Connection<Octs>> {
        let connection = InnerConnection::new(remote_addr)?;
        Ok(Self {
            inner: Arc::new(connection),
        })
    }

    /// Worker function for a connection object.
    pub async fn run(&self) -> Option<()> {
        self.inner.run().await
    }

    /// Start a query.
    pub async fn query(
        &self,
        query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
    ) -> Result<Query<Octs>, &'static str> {
        self.inner.query(query_msg).await
    }
}

/// Object that contains the current state of a query.
pub struct Query<Octs: Debug + OctetsBuilder> {
    /// Reqeust message.
    query_msg: MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,

    /// UDP transport to be used.
    udp_conn: udp::Connection,

    /// TCP transport to be used.
    tcp_conn: multi_stream::Connection<Octs>,

    /// Current state of the query.
    state: QueryState<Octs>,
}

/// Status of the query.
enum QueryState<Octs: Debug + OctetsBuilder> {
    /// Start a query over the UDP transport.
    StartUdpQuery,

    /// Get the result from the UDP transport.
    GetUdpResult(udp::Query<Octs>),

    /// Start a query over the TCP transport.
    StartTcpQuery,

    /// Get the result from the TCP transport.
    GetTcpResult(multi_stream::Query<Octs>),
}

impl<
        Octs: AsMut<[u8]>
            + AsRef<[u8]>
            + Clone
            + Composer
            + Debug
            + OctetsBuilder
            + Send
            + 'static,
    > Query<Octs>
{
    /// Create a new Query object.
    ///
    /// The initial state is to start with a UDP transport.
    fn new(
        query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
        udp_conn: udp::Connection,
        tcp_conn: multi_stream::Connection<Octs>,
    ) -> Query<Octs> {
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
    pub async fn get_result(
        &mut self,
    ) -> Result<Message<Bytes>, Arc<std::io::Error>> {
        loop {
            match &mut self.state {
                QueryState::StartUdpQuery => {
                    let query = self
                        .udp_conn
                        .query(&mut self.query_msg.clone())
                        .await
                        .map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, e)
                        })?;
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
                    let query = self
                        .tcp_conn
                        .query(&mut self.query_msg.clone())
                        .await
                        .map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, e)
                        })?;
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

/// The actual connection object.
struct InnerConnection<Octs: Debug + OctetsBuilder> {
    /// The remote address to connect to.
    remote_addr: SocketAddr,

    /// The UDP transport connection.
    udp_conn: udp::Connection,

    /// The TCP transport connection.
    tcp_conn: multi_stream::Connection<Octs>,
}

impl<Octs: Clone + Composer + Debug + OctetsBuilder + Send + 'static>
    InnerConnection<Octs>
{
    /// Create a new InnerConnection object.
    ///
    /// Create the UDP and TCP connections. Store the remote address because
    /// run needs it later.
    fn new(remote_addr: SocketAddr) -> io::Result<InnerConnection<Octs>> {
        let udp_conn = udp::Connection::new(remote_addr)?;
        let tcp_conn = multi_stream::Connection::new()?;

        Ok(Self {
            remote_addr,
            udp_conn,
            tcp_conn,
        })
    }

    /// Implementation of the worker function.
    ///
    /// Create a TCP connection factory and pass that to worker function
    /// of the multi_stream object.
    pub async fn run(&self) -> Option<()> {
        let tcp_factory = TcpConnFactory::new(self.remote_addr);
        self.tcp_conn.run(tcp_factory).await
    }

    /// Implementation of the query function.
    ///
    /// Just create a Query object with the state it needs.
    async fn query(
        &self,
        query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
    ) -> Result<Query<Octs>, &'static str> {
        Ok(Query::new(
            query_msg,
            self.udp_conn.clone(),
            self.tcp_conn.clone(),
        ))
    }
}
