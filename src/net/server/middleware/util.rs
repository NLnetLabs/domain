use core::ops::DerefMut;

use std::future::Ready;

use futures::stream::{FuturesOrdered, Once};
use futures::Stream;
use futures_util::StreamExt;

use crate::base::wire::Composer;
use crate::net::server::service::{CallResult, ServiceError};

pub enum MiddlewareStream<
    InnerServiceResponseStream,
    PostprocessingStream,
    Target,
> where
    InnerServiceResponseStream: futures::stream::Stream<
            Item = Result<CallResult<Target>, ServiceError>,
        > + Unpin,
    PostprocessingStream: futures::stream::Stream<
            Item = Result<CallResult<Target>, ServiceError>,
        > + Unpin,
    Self: Unpin,
    Target: Unpin,
{
    /// The inner service response will be passed through this service without
    /// modification.
    Passthru(InnerServiceResponseStream),

    /// The inner service response will be post-processed by this service.
    Postprocess(PostprocessingStream),

    /// A single response has been created without invoking the inner service.
    HandledOne(Once<Ready<Result<CallResult<Target>, ServiceError>>>),

    /// Multiple responses have been created without invoking the inner
    /// service.
    HandledMany(
        FuturesOrdered<Ready<Result<CallResult<Target>, ServiceError>>>,
    ),
}

impl<InnerServiceResponseStream, PostprocessingStream, Target> Stream
    for MiddlewareStream<
        InnerServiceResponseStream,
        PostprocessingStream,
        Target,
    >
where
    InnerServiceResponseStream: futures::stream::Stream<
            Item = Result<CallResult<Target>, ServiceError>,
        > + Unpin,
    PostprocessingStream: futures::stream::Stream<
            Item = Result<CallResult<Target>, ServiceError>,
        > + Unpin,
    Target: Composer + Default + Unpin,
{
    type Item = Result<CallResult<Target>, ServiceError>;

    fn poll_next(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Self::Item>> {
        match self.deref_mut() {
            MiddlewareStream::Passthru(s) => s.poll_next_unpin(cx),
            MiddlewareStream::Postprocess(s) => s.poll_next_unpin(cx),
            MiddlewareStream::HandledOne(s) => s.poll_next_unpin(cx),
            MiddlewareStream::HandledMany(s) => s.poll_next_unpin(cx),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            MiddlewareStream::Passthru(s) => s.size_hint(),
            MiddlewareStream::Postprocess(s) => s.size_hint(),
            MiddlewareStream::HandledOne(s) => s.size_hint(),
            MiddlewareStream::HandledMany(s) => s.size_hint(),
        }
    }
}
