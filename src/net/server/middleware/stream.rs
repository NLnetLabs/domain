use core::future::Future;
use core::ops::DerefMut;
use core::task::{ready, Context, Poll};

use std::pin::Pin;

use futures_util::future::FutureExt;
use futures_util::stream::{Stream, StreamExt};
use octseq::Octets;
use tracing::trace;

use crate::net::server::message::Request;

//------------ MiddlewareStream ----------------------------------------------

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
    /// without modification, resolving the future first and then the
    /// resulting IdentityStream next.
    IdentityFuture(IdentityFuture),

    /// The inner service response stream will be passed through this service
    /// without modification.
    IdentityStream(IdentityStream),

    /// Either a single response has been created without invoking the inner
    /// service, or the inner service response will be post-processed by this
    /// service.
    Map(MapStream),

    /// A response has been created without invoking the inner service.
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
    Stream: futures_util::stream::Stream,
    Future: core::future::Future<Output = Stream>,
{
    Pending(Future),
    Streaming(Stream),
}

//------------ PostprocessingStreamCallback ----------------------------------

type PostprocessingStreamCallback<
    RequestOctets,
    StreamItem,
    RequestMeta,
    PostProcessingMeta,
> = fn(
    Request<RequestOctets, RequestMeta>,
    StreamItem,
    PostProcessingMeta,
) -> StreamItem;

//------------ PostprocessingStream ------------------------------------------

pub struct PostprocessingStream<
    RequestOctets,
    Future,
    Stream,
    RequestMeta,
    PostProcessingMeta,
> where
    RequestOctets: Octets + Send + Sync + Unpin,
    Future: core::future::Future<Output = Stream>,
    Stream: futures_util::stream::Stream,
{
    request: Request<RequestOctets, RequestMeta>,
    state: PostprocessingStreamState<Future, Stream>,
    cb: PostprocessingStreamCallback<
        RequestOctets,
        Stream::Item,
        RequestMeta,
        PostProcessingMeta,
    >,
    pp_meta: PostProcessingMeta,
}

impl<RequestOctets, Future, Stream, RequestMeta, PostProcessingMeta>
    PostprocessingStream<
        RequestOctets,
        Future,
        Stream,
        RequestMeta,
        PostProcessingMeta,
    >
where
    RequestOctets: Octets + Send + Sync + Unpin,
    Future: core::future::Future<Output = Stream>,
    Stream: futures_util::stream::Stream,
{
    pub fn new(
        svc_call_fut: Future,
        request: Request<RequestOctets, RequestMeta>,
        metadata: PostProcessingMeta,
        cb: PostprocessingStreamCallback<
            RequestOctets,
            Stream::Item,
            RequestMeta,
            PostProcessingMeta,
        >,
    ) -> Self {
        Self {
            state: PostprocessingStreamState::Pending(svc_call_fut),
            request,
            cb,
            pp_meta: metadata,
        }
    }
}

//--- impl Stream

impl<RequestOctets, Future, Stream, RequestMeta, PostProcessingMeta>
    futures_util::stream::Stream
    for PostprocessingStream<
        RequestOctets,
        Future,
        Stream,
        RequestMeta,
        PostProcessingMeta,
    >
where
    RequestOctets: Octets + Send + Sync + Unpin,
    Future: core::future::Future<Output = Stream> + Unpin,
    Stream: futures_util::stream::Stream + Unpin,
    Self: Unpin,
    RequestMeta: Clone,
    PostProcessingMeta: Clone,
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
                let pp_meta = self.pp_meta.clone();
                let map =
                    stream_item.map(|item| (self.cb)(request, item, pp_meta));
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
