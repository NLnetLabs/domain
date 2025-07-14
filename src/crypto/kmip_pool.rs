#![cfg(feature = "kmip")]
#![cfg_attr(docsrs, doc(cfg(feature = "kmip")))]

//! KMIP TLS connection pool
//!
//! Used to:
//!  - Avoid repeated TCP connection setup and TLS session establishment
//!    for mutiple KMIP requests made close together in time.
//!  - Handle loss of connectivity by re-creating the connection when an
//!    existing connection is considered to be "broken" at the network
//!    level.
use core::fmt::Display;
use core::ops::Deref;
use std::net::TcpStream;
use std::string::String;
use std::{sync::Arc, time::Duration};

use kmip::client::{Client, ConnectionSettings};
// TODO: Remove the hard-coded use of OpenSSL?
use openssl::ssl::SslStream;
use r2d2::PooledConnection;

//------------ KmipConnError -------------------------------------------------

#[derive(Clone, Debug)]
pub struct KmipConnError(String);

impl From<r2d2::Error> for KmipConnError {
    fn from(err: r2d2::Error) -> Self {
        Self(format!("{err}"))
    }
}

impl Display for KmipConnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//------------ KmipConn ------------------------------------------------------

/// A KMIP connection pool connection.
pub struct KmipConn {
    conn: PooledConnection<ConnectionManager>,
}

impl KmipConn {
    fn new(conn: PooledConnection<ConnectionManager>) -> Self {
        Self { conn }
    }
}

impl Deref for KmipConn {
    type Target = KmipTlsClient;

    fn deref(&self) -> &Self::Target {
        self.conn.deref()
    }
}

/// A KMIP client used to send KMIP requests and receive KMIP responses.
///
/// Note: Currently depends on OpenSSL because our KMIP implementation
/// supports elements of KMIP 1.2 [1] but not KMIP 1.3 [2], but prior to KMIP
/// 1.3 it is required for servers to support TLS 1.0, and RustLS doesn't
/// support TLS < 1.2.
///
/// [1]: https://docs.oasis-open.org/kmip/profiles/v1.2/os/kmip-profiles-v1.2-os.html#_Toc409613167
/// [2]: https://docs.oasis-open.org/kmip/profiles/v1.3/os/kmip-profiles-v1.3-os.html#_Toc473103053
pub type KmipTlsClient = Client<SslStream<TcpStream>>;

/// A pool of already connected KMIP clients.
///
/// This pool can be used to acquire a KMIP client without first having to
/// wait for it to connect at the TCP/TLS level, and without unnecessarily
/// closing the connection when finished.
#[derive(Clone, Debug)]
pub struct KmipConnPool {
    server_id: String,
    conn_settings: Arc<ConnectionSettings>,
    pool: r2d2::Pool<ConnectionManager>,
}

impl KmipConnPool {
    pub fn new(
        server_id: String,
        conn_settings: Arc<ConnectionSettings>,
        max_conncurrent_connections: u32,
        max_life_time: Option<Duration>,
        max_idle_time: Option<Duration>,
    ) -> Result<KmipConnPool, KmipConnError> {
        let pool = r2d2::Pool::builder()
            // Don't pre-create idle connections to the KMIP server
            .min_idle(Some(0))
            // Create at most this many concurrent connections to the KMIP
            // server
            .max_size(max_conncurrent_connections)
            // Don't verify that a connection is usable when fetching it from
            // the pool (as doing so requires sending a request to the server
            // and we might as well just try the actual request that we want
            // the connection for)
            .test_on_check_out(false)
            // Don't use the default logging behaviour as `[ERROR] [r2d2]
            // Server error: ...` is a bit confusing for end users who
            // shouldn't know or care that we use the r2d2 crate.
            // .error_handler(Box::new(ErrorLoggingHandler))
            // Don't keep using the same connection for longer than around N
            // minutes (unless in use in which case it will wait until the
            // connection is returned to the pool before closing it) - maybe
            // long held connections would run into problems with some
            // firewalls.
            .max_lifetime(max_life_time)
            // Don't keep connections open that were not used in the last N
            // minutes.
            .idle_timeout(max_idle_time)
            // Don't wait longer than N seconds for a new connection to be
            // established, instead try again to connect.
            .connection_timeout(
                conn_settings
                    .connect_timeout
                    .unwrap_or(Duration::from_secs(30)),
            )
            // Use our connection manager to create connections in the pool
            // and to verify their health
            .build(ConnectionManager {
                conn_settings: conn_settings.clone(),
            })?;

        Ok(Self {
            server_id,
            conn_settings,
            pool,
        })
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn conn_settings(&self) -> &ConnectionSettings {
        &self.conn_settings
    }

    pub fn get(&self) -> Result<KmipConn, KmipConnError> {
        Ok(KmipConn::new(self.pool.get()?))
    }
}

/// Manages KMIP TCP + TLS connection creation.
///
/// Uses the [r2d2] crate to manage a pool of connections.
///
/// [r2d2]: https://crates.io/crates/r2d2/
#[derive(Debug)]
pub struct ConnectionManager {
    conn_settings: Arc<ConnectionSettings>,
}

impl ConnectionManager {
    /// Create a pool of up-to N TCP + TLS connections to the KMIP server.
    #[rustfmt::skip]
    pub fn create_connection_pool(
        server_id: String,
        conn_settings: Arc<ConnectionSettings>,
        max_conncurrent_connections: u32,
        max_life_time: Option<Duration>,
        max_idle_time: Option<Duration>,
    ) -> Result<KmipConnPool, KmipConnError> {
        Ok(KmipConnPool::new(
            server_id,
            conn_settings,
            max_conncurrent_connections,
            max_life_time,
            max_idle_time
        )?)
    }

    /// Connect using the given connection settings to a KMIP server.
    ///
    /// This function creates a new connection to the server. The connection
    /// is NOT taken from the connection pool.
    pub fn connect_one_off(
        settings: &ConnectionSettings,
    ) -> kmip::client::Result<KmipTlsClient> {
        let conn = kmip::client::tls::openssl::connect(settings)?;
        Ok(conn)
    }
}

impl r2d2::ManageConnection for ConnectionManager {
    type Connection = KmipTlsClient;

    type Error = kmip::client::Error;

    /// Establishes a KMIP server connection which will be added to the
    /// connection pool.
    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        Self::connect_one_off(&self.conn_settings)
    }

    /// This function is never used because the [r2d2] `test_on_check_out`
    /// flag is set to false when the connection pool is created.
    ///
    /// [r2d2]: https://crates.io/crates/r2d2/
    fn is_valid(
        &self,
        _conn: &mut Self::Connection,
    ) -> Result<(), Self::Error> {
        unreachable!()
    }

    /// Quickly verify if an existing connection is broken.
    ///
    /// Used to discard and re-create connections that encounter multiple
    /// connection related errors.
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.connection_error_count() > 1
    }
}

// /// A Krill specific [r2d2] error logging handler.
// ///
// /// Logs connection pool related connection error messages using the format
// /// `"[<LEVEL>] Pool error: ..."` instead of
// /// the default [r2d2] `"[ERROR] [r2d2] Server error: ..."` format. Assumes
// /// that the logging framework will include the logging module context in the
// /// logged message, i.e. `xxx::kmip::xxx` and thus we don't need to mention
// /// KMIP in the logged message content.
// ///
// /// Rationale:
// ///   - The use of the [r2d2] crate is an internal detail which of no use to
// ///     end users consulting the logs and which we may change at any time.
// ///   - Krill should be the one to determine the appropriate level to log a
// ///     connection issue at, not [r2d2].
// #[derive(Debug)]
// struct ErrorLoggingHandler;

// impl<E> r2d2::HandleError<E> for ErrorLoggingHandler
// where
//     E: std::fmt::Display,
// {
//     fn handle_error(&self, err: E) {
//         warn!("Pool error: {}", err)
//     }
// }

// impl From<r2d2::Error> for SignerError {
//     fn from(err: r2d2::Error) -> Self {
//         SignerError::KmipError(format!("{}", err))
//     }
// }
