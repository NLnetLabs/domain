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
use std::net::TcpStream;
use std::{sync::Arc, time::Duration};

use kmip::client::{Client, ConnectionSettings};
use openssl::ssl::SslStream;

pub type KmipTlsClient = Client<SslStream<TcpStream>>;

pub type KmipConnPool = r2d2::Pool<ConnectionManager>;

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
        conn_settings: Arc<ConnectionSettings>,
        max_response_bytes: u32,
        max_life_time: Duration,
        max_idle_time: Duration,
    ) -> Result<KmipConnPool, ()> {
        let max_life_time = Some(max_life_time);
        let max_idle_time = Some(max_idle_time);

        let pool = r2d2::Pool::builder()
            // Don't pre-create idle connections to the KMIP server
            .min_idle(Some(0))

            // Create at most this many concurrent connections to the KMIP server
            .max_size(max_response_bytes)

            // Don't verify that a connection is usable when fetching it from the pool (as doing so requires sending a
            // request to the server and we might as well just try the actual request that we want the connection for)
            .test_on_check_out(false)

            // Don't use the default logging behaviour as `[ERROR] [r2d2] Server error: ...` is a bit confusing for end
            // users who shouldn't know or care that we use the r2d2 crate.
            // .error_handler(Box::new(ErrorLoggingHandler))

            // Don't keep using the same connection for longer than around N minutes (unless in use in which case it
            // will wait until the connection is returned to the pool before closing it) - maybe long held connections
            // would run into problems with some firewalls.
            .max_lifetime(max_life_time)

            // Don't keep connections open that were not used in the last N minutes.
            .idle_timeout(max_idle_time)

            // Don't wait longer than N seconds for a new connection to be established, instead try again to connect.
            .connection_timeout(conn_settings.connect_timeout.unwrap_or(Duration::from_secs(30)))

            // Use our connection manager to create connections in the pool and to verify their health
            .build(ConnectionManager { conn_settings }).unwrap();

        Ok(pool)
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
