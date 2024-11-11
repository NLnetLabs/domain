use tracing_subscriber::EnvFilter;

/// Setup logging of events reported by domain and the test suite.
///
/// Use the RUST_LOG environment variable to override the defaults.
///
/// E.g. To enable debug level logging:
///   RUST_LOG=DEBUG
///
/// Or to log only the steps processed by the Stelline client:
///   RUST_LOG=net_server::net::stelline::client=DEBUG
///
/// Or to enable trace level logging but not for the test suite itself:
///   RUST_LOG=TRACE,net_server=OFF
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();
}
