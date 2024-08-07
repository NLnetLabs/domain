//! Support for working with response streams needed by all middleware.
//!
//! Like application services all middleware implementations implement the
//! [`Service`] trait and so return a [`futures::stream::Stream`] of
//! responses.
//!
//! A middleware [`Service`] may respond immediately, or pass the request to
//! the next [`Service`] above and then handle the response or responses
//! returned by the upper layer, either passing them through unchanged or
//! post-processing them depending on the purpose of the middleware.
//!
//! Unlike an application service, middleware is not completely in control of
//! the type of response stream that it returns, and may even return a
//! different type in different circumstances. A middleware that passes the
//! responses from the upper service through unchanged must return whatever
//! type of response stream the upper service generates. A middleware that
//! responds immediately returns its own type of response stream. And
//! middleware that post-processes responses received from the upper service
//! may transform the upper service response type to a different response
//! type.
//!
//! The [`MiddlewareStream`] and [`PostprocessingStream`] types provided by
//! this module are intended to simplify and standardize the way that
//! middleware implementations handle these cases.
//!
//! [`futures::stream::Stream`]: futures::stream::Stream
//! [`Service`]: crate::net::server::service::Service
use core::future::Future;
use core::ops::DerefMut;
use core::task::{ready, Context, Poll};

use std::pin::Pin;

use futures::prelude::future::FutureExt;
use futures::stream::{Stream, StreamExt};
use octseq::Octets;
use tracing::trace;

use crate::net::server::message::Request;

//------------ MiddlewareStream ----------------------------------------------

/// A [`futures::stream::Stream`] of middleware responses.
///
/// A middleware [`Service`] must be able to respond with different types of
/// response streams depending on the received request or on post-processing
/// applied to responses received from the upper service.
///
/// It is not sufficient therefore to define a single `Service::Stream` type
/// for a middleware [`Service`] impl. Instead middleware should return the
/// [`MiddlewareStream`] enum type which is able to represent the different
/// variants of response stream that may result from middleware processing:
///
/// [`futures::stream::Stream`]: futures::stream::Stream
/// [`Service`]: crate::net::server::service::Service
pub enum MiddlewareStream<
    IdentityFuture,
    IdentityStream,
    MapStream,
    ResultStream,
    StreamItem,
> where
    IdentityFuture: Future<Output = IdentityStream>,
    IdentityStream: Stream<Item = StreamItem>,
    MapStream: Stream<Item = StreamItem>,
    ResultStream: Stream<Item = StreamItem>,
{
    /// The inner service response future will be passed through this service
    /// without modification, resolving the future into an IdentityStream.
    IdentityFuture(IdentityFuture),

    /// The inner service response stream will be passed through this service
    /// without modification.
    IdentityStream(IdentityStream),

    /// Either a single response has been created without invoking the inner
    /// service, or the inner service response will be post-processed by this
    /// service. In both cases the response stream is potentially a different
    /// type than that of the upper service, i.e. the upper service response
    /// stream type is said to be "mapped" to a different response stream
    /// type.
    Map(MapStream),

    /// A response has been created without invoking the inner service. Its
    /// type may be different to that of the upper service response stream and
    /// so is referred to as a "result" stream.
    Result(ResultStream),
}

//--- impl Stream

impl<IdentityFuture, IdentityStream, MapStream, ResultStream, StreamItem>
    Stream
    for MiddlewareStream<
        IdentityFuture,
        IdentityStream,
        MapStream,
        ResultStream,
        StreamItem,
    >
where
    IdentityFuture: Future<Output = IdentityStream> + Unpin,
    IdentityStream: Stream<Item = StreamItem> + Unpin,
    MapStream: Stream<Item = StreamItem> + Unpin,
    ResultStream: Stream<Item = StreamItem> + Unpin,
    Self: Unpin,
{
    type Item = StreamItem;

    fn poll_next(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.deref_mut() {
            MiddlewareStream::IdentityFuture(f) => {
                let stream = ready!(f.poll_unpin(cx));
                *self = MiddlewareStream::IdentityStream(stream);
                self.poll_next(cx)
            }
            MiddlewareStream::IdentityStream(s) => s.poll_next_unpin(cx),
            MiddlewareStream::Map(s) => s.poll_next_unpin(cx),
            MiddlewareStream::Result(s) => s.poll_next_unpin(cx),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            MiddlewareStream::IdentityFuture(_) => (0, None),
            MiddlewareStream::IdentityStream(s) => s.size_hint(),
            MiddlewareStream::Map(s) => s.size_hint(),
            MiddlewareStream::Result(s) => s.size_hint(),
        }
    }
}

//------------ PostprocessingStreamState -------------------------------------

enum PostprocessingStreamState<Future, Stream>
where
    Stream: futures::stream::Stream,
    Future: core::future::Future<Output = Stream>,
{
    Pending(Future),
    Streaming(Stream),
}

//------------ PostprocessingStreamCallback ----------------------------------

type PostprocessingStreamCallback<RequestOctets, StreamItem, Metadata> =
    fn(Request<RequestOctets>, StreamItem, Metadata) -> StreamItem;

//------------ PostprocessingStream ------------------------------------------

/// A [`futures::stream::Stream`] that post-processes responses using a
/// provided callback.
///
/// To post-process an upper service response stream one must first resolve
/// the `Service::Future` into a `Service::Stream` and then apply transforming
/// logic to each of the response stream items as they are received one by one
/// in streaming fashion.
///
/// This type takes care of these details for you so that you can focus on
/// defining the transformation logic via a user supplied callback function
/// which will be invoked on each received response stream item.
///
/// [`futures::stream::Stream`]: futures::stream::Stream
pub struct PostprocessingStream<RequestOctets, Future, Stream, Metadata>
where
    RequestOctets: Octets + Send + Sync + Unpin,
    Future: core::future::Future<Output = Stream>,
    Stream: futures::stream::Stream,
{
    request: Request<RequestOctets>,
    state: PostprocessingStreamState<Future, Stream>,
    cb: PostprocessingStreamCallback<RequestOctets, Stream::Item, Metadata>,
    metadata: Metadata,
}

impl<RequestOctets, Future, Stream, Metadata>
    PostprocessingStream<RequestOctets, Future, Stream, Metadata>
where
    RequestOctets: Octets + Send + Sync + Unpin,
    Future: core::future::Future<Output = Stream>,
    Stream: futures::stream::Stream,
{
    /// Creates a new post-processing stream.
    ///
    /// The created post-processing stream will resolve the given
    /// `Service::Future` to its `Service::Stream` type and then invoke the
    /// given callback on each item in the stream one by one.
    ///
    /// As the original request that resulted in the response stream is often
    /// needed in post-processing, e.g. to copy properties of the request to
    /// the response, or to vary the behaviour based on the request transport,
    /// you must supply the original request when calling this function.
    ///
    /// You may also supply user defined metadata which will be made available
    /// to the callback each time it is invoked.
    pub fn new(
        svc_call_fut: Future,
        request: Request<RequestOctets>,
        metadata: Metadata,
        cb: PostprocessingStreamCallback<
            RequestOctets,
            Stream::Item,
            Metadata,
        >,
    ) -> Self {
        Self {
            state: PostprocessingStreamState::Pending(svc_call_fut),
            request,
            cb,
            metadata,
        }
    }
}

//--- impl Stream

impl<RequestOctets, Future, Stream, Metadata> futures::stream::Stream
    for PostprocessingStream<RequestOctets, Future, Stream, Metadata>
where
    RequestOctets: Octets + Send + Sync + Unpin,
    Future: core::future::Future<Output = Stream> + Unpin,
    Stream: futures::stream::Stream + Unpin,
    Self: Unpin,
    Metadata: Clone,
{
    type Item = Stream::Item;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match &mut self.state {
            PostprocessingStreamState::Pending(svc_call_fut) => {
                let stream = ready!(svc_call_fut.poll_unpin(cx));
                trace!("Stream has become available");
                self.state = PostprocessingStreamState::Streaming(stream);
                self.poll_next(cx)
            }
            PostprocessingStreamState::Streaming(stream) => {
                let stream_item = ready!(stream.poll_next_unpin(cx));
                trace!("Stream item retrieved, mapping to downstream type");
                let request = self.request.clone();
                let metadata = self.metadata.clone();
                let map = stream_item
                    .map(|item| (self.cb)(request, item, metadata));
                Poll::Ready(map)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.state {
            PostprocessingStreamState::Pending(_fut) => (0, None),
            PostprocessingStreamState::Streaming(stream) => {
                stream.size_hint()
            }
        }
    }
}
