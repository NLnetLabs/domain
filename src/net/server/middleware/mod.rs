//! Request pre-processing and response post-processing.
//!
//! Middleware sits in the middle between the server nearest the client and
//! the [`Service`] that implements the application logic.
//!
//! Middleware pre-processes requests and post-processes responses to
//! filter/reject/modify them according to policy and standards.
//!
//! Middleware processing should happen immediately after receipt of a request
//! (to ensure the least resources are spent on processing malicious requests)
//! and immediately prior to writing responses back to the client (to ensure
//! that what is sent to the client is correct).
//!
//! Mandatory functionality and logic required by all standards compliant DNS
//! servers can be incorporated into your server by building a middleware
//! chain starting from [`MiddlewareBuilder::default`].
//!
//! A selection of additional functionality relating to server behaviour and
//! DNS standards (as opposed to your own application logic) is provided which
//! you can incorporate into your DNS server via [`MiddlewareBuilder::push`].
//! See the various implementations of [`MiddlewareProcessor`] for more
//! information.
//!
//! [`MiddlewareBuilder::default`]: builder::MiddlewareBuilder::default()
//! [`MiddlewareBuilder::push`]: builder::MiddlewareBuilder::push()
//! [`MiddlewareChain`]: chain::MiddlewareChain
//! [`MiddlewareProcessor`]: processor::MiddlewareProcessor
//! [`Service`]: crate::net::server::service::Service
pub mod builder;
pub mod chain;
pub mod processor;
pub mod processors;
pub mod util;
