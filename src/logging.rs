//! Common logging functions

/// Setup logging of events reported by domain and the test suite.
///
/// Use the RUST_LOG environment variable to override the defaults.
///
/// E.g. To enable debug level logging:
///
/// ```bash
/// RUST_LOG=DEBUG
/// ```
#[cfg(feature = "tracing-subscriber")]
#[allow(dead_code)]
pub fn init_logging() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        // Useful sometimes:
        // .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .try_init()
        .ok();
}
