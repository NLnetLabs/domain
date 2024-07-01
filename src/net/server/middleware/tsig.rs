//! XFR request handling middleware.

// TODO: Factor (A/I)XFR out to src/net/server/xfr.rs.
use core::future::{ready, Future, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;
use core::pin::Pin;

use std::boxed::Box;
use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{once, Once, Stream};
use octseq::Octets;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::Semaphore;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{error, info, trace, warn};

use crate::base::iana::{Opcode, OptRcode, Rcode};
use crate::base::message_builder::{
    AdditionalBuilder, AnswerBuilder, PushError,
};
use crate::base::net::IpAddr;
use crate::base::record::ComposeRecord;
use crate::base::wire::Composer;
use crate::base::{
    Message, Name, ParsedName, Question, Rtype, Serial, StreamTarget, ToName,
};
use crate::net::server::message::Request;
use crate::net::server::service::{
    CallResult, Service, ServiceFeedback, ServiceResult,
};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::ZoneRecordData;
use crate::zonecatalog::catalog::{
    Catalog, CatalogZone, CompatibilityMode, Syncable, SyncableZone,
    XfrOutConnFactory, XfrSettings, XfrStrategy, ZoneInfo,
};
use crate::zonetree::error::OutOfZone;
use crate::zonetree::{
    Answer, AnswerContent, ReadableZone, SharedRrset, StoredName,
};

use super::stream::MiddlewareStream;
use crate::tsig::KeyStore;

//------------ XfrMapStream --------------------------------------------------

type XfrResultStream<StreamItem> = UnboundedReceiverStream<StreamItem>;

//------------ XfrMiddlewareStream -------------------------------------------

type XfrMiddlewareStream<Future, Stream, StreamItem> = MiddlewareStream<
    Future,
    Stream,
    Once<Ready<StreamItem>>,
    XfrResultStream<StreamItem>,
    StreamItem,
>;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum XfrMode {
    AxfrAndIxfr,
    AxfrOnly,
}

//------------ TsigMiddlewareSvc ----------------------------------------------

/// A [`MiddlewareProcessor`] for validating TSIG authenticated requests.
///
/// Standards covered by ths implementation:
///
/// | RFC    | Status  |
/// |--------|---------|
/// | TBD    | TBD     |
#[derive(Clone, Debug)]
pub struct TsigMiddlewareSvc<RequestOctets, Svc, Store> {
    svc: Svc,

    key_store: Arc<Store>,

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, Svc, Store> TsigMiddlewareSvc<RequestOctets, Svc, Store> {
    /// Creates an empty processor instance.
    #[must_use]
    pub fn new(svc: Svc, key_store: Arc<Store>) -> Self {
        Self {
            svc,
            key_store,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, Svc, Store> TsigMiddlewareSvc<RequestOctets, Svc, Store>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    Svc: Service<RequestOctets>,
    Svc::Target: Composer + Default + Send + Sync + 'static,
    Store: KeyStore,
{
    async fn preprocess(
        req: &Request<RequestOctets>,
        key_store: Arc<Store>,
    ) -> ControlFlow<
        MiddlewareStream<
            Svc::Future,
            Svc::Stream,
            PostprocessingStream<RequestOctets, Svc::Future, Svc::Stream, ()>,
            Once<Ready<<Svc::Stream as Stream>::Item>>,
            <Svc::Stream as Stream>::Item,
        >,
    > {
        todo!()
    }

    fn postprocess(
        request: &Request<RequestOctets>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) {
        todo!()
    }

    fn map_stream_item(
        request: Request<RequestOctets>,
        mut stream_item: ServiceResult<Svc::Target>,
        _metadata: (),
    ) -> ServiceResult<Svc::Target> {
        if let Ok(cr) = &mut stream_item {
            if let Some(response) = cr.response_mut() {
                Self::postprocess(&request, response);
            }
        }
        stream_item
    }
}

//--- Service

impl<RequestOctets, Svc> Service<RequestOctets>
    for TsigMiddlewareSvc<RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    Svc: Service<RequestOctets> + Clone + 'static + Send + Sync + Unpin,
    Svc::Future: Send + Sync + Unpin,
    Svc::Target: Composer + Default + Send + Sync,
    Svc::Stream: Send + Sync,
{
    type Target = Svc::Target;
    type Stream = MiddlewareStream<
        Svc::Future,
        Svc::Stream,
        Svc::Stream,
        Once<Ready<<Svc::Stream as Stream>::Item>>,
        <Svc::Stream as Stream>::Item,
    >;
    type Future = core::future::Ready<Self::Stream>;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send + Sync>>;

    fn call(&self, request: Request<RequestOctets>) -> Self::Future {
        let request = request.clone();
        let svc = self.svc.clone();
        let key_store = self.key_store.clone();
        Box::pin(async move {
            match Self::preprocess(&request, key_store).await {
                ControlFlow::Continue(()) => {
                    let svc_call_fut = self.svc.call(request.clone());
                    let map = PostprocessingStream::new(
                        svc_call_fut,
                        request,
                        (),
                        Self::map_stream_item,
                    );
                    ready(MiddlewareStream::Map(map))
                }
                ControlFlow::Break(stream) => stream,
            }
        })
    }
}
