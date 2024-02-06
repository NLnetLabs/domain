use std::sync::Arc;

use crate::net::server::{
    buf::BufSource, error::Error, metrics::ServerMetrics,
    middleware::chain::MiddlewareChain,
};

use super::service::Service;

//----------- Server --------------------------------------------------------

/// A trait for dealing with DNS server implementations.
/// 
/// <div class="warning"><b>A note about async functions</b>
/// 
/// Some functions common to DNS server implementations are async. However, at
/// the time of writing the minimum supported Rust version for this crate
/// doesn't support async (or desugared async) functions in traits. 
/// 
/// Therefore some functions that ideally would be part of the [`Server`]
/// trait, such as [`run()`], are not actually defined in the [`Server`] trait
/// but instead exist only in the concrete implementations.
/// 
/// </div>
/// 
/// [`run()`]: crate::net::server::servers::dgram::server::DgramServer::run()
pub trait Server<Source, Buf, Svc>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    #[must_use]
    fn new(source: Source, buf: Arc<Buf>, service: Arc<Svc>) -> Self;

    #[must_use]
    fn with_middleware(
        self,
        middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
    ) -> Self;

    /// Get a reference to the source for this server.
    #[must_use]
    fn source(&self) -> Arc<Source>;

    /// Get a reference to the metrics for this server.
    #[must_use]
    fn metrics(&self) -> Arc<ServerMetrics>;

    /// Stop the server.
    fn shutdown(&self) -> Result<(), Error>;
}
