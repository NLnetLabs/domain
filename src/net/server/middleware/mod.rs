//! Request pre-processing and response post-processing middleware.
//!
//! Middleware sits between the server and the application [`Service`],
//! pre-processing requests and post-processing responses in order to
//! filter/reject/modify them according to policy and standards.
//!
//! Middleware is implemented in terms of the [`Service`] trait, just like
//! your application service, but also takes a [`Service`] instance as an
//! argument.
//!
//! This extra argument enables middleware to be composed in layers one atop
//! another, each layer receiving and pre-processing requests from the layer
//! beneath, passing them on to the layer above and then post-processing the
//! resulting responses and propagating them back down through the layers to
//! the server.
//!
//! A middleware service may also choose to respond immediately to a request
//! without passing it to the layer above. This could be because the
//! middleware determines that the request is invalid, or because the
//! middleware is able to handle and respond to the request entirely on its
//! own.
//!
//! # Middleware layering strategies
//!
//! The simplest strategy for using middleware is to use a single layered
//! stack of middleware for all incoming requests.
//!
//! If however some middleware layers impose a disproportionately high cost on
//! request processing for request types that occur rarely, an alternate
//! strategy could be to add a middleware layer that routes requests to the
//! appropriate middleware "chain" based on some property or properties of the
//! request. Rather than a liner processing "chain" one would then have a tree
//! like processing path.
//!
//! Another option that may be suitable in some cases could be to use separate
//! server instances listening on separate ports or interfaces, each with
//! their own differing middleware "chains".
//!
//! # Middleware-to-middleware communication
//!
//! If needed middleware services can pass service specific data to upstream
//! services for consumption, via the  `RequestMeta` custom data support of
//! the [`Service`] trait. An example of this can be seen in the
//! [`TsigMiddlewareSvc`][tsig::TsigMiddlewareSvc].
//!
//! Currently the following middleware are available:
//!
//! [`Service`]: crate::net::server::service::Service
#[cfg(feature = "siphasher")]
pub mod cookies;
pub mod edns;
pub mod mandatory;
pub mod notify;
pub mod stream;
#[cfg(feature = "tsig")]
pub mod tsig;
#[cfg(feature = "unstable-xfr")]
pub mod xfr;
