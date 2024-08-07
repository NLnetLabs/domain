use core::future::Future;
use core::ops::ControlFlow;
use core::pin::Pin;

use std::boxed::Box;

use futures::stream::Stream;
use octseq::Octets;

use crate::base::wire::Composer;
use crate::net::server::message::Request;
use crate::net::server::middleware::stream::MiddlewareStream;
use crate::net::server::service::Service;
use crate::tsig::KeyName;
use crate::zonemaintenance::maintainer::ZoneLookup;

use super::processor::XfrMiddlewareSvc;
use super::types::XfrMiddlewareStream;

//--- Service (with TSIG key name in the request metadata)

pub trait MaybeAuthenticated:
    Clone + Default + Sync + Send + 'static
{
    fn key(&self) -> Option<&KeyName>;
}

impl<RequestOctets, NextSvc, ZL, MetaType> Service<RequestOctets, MetaType>
    for XfrMiddlewareSvc<RequestOctets, NextSvc, ZL>
where
    RequestOctets: Octets + Send + Sync + Unpin + 'static,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, ()> + Clone + Send + Sync + 'static,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    NextSvc::Stream: Send + Sync,
    ZL: ZoneLookup + Clone + Sync + Send + 'static,
    MetaType: MaybeAuthenticated,
{
    type Target = NextSvc::Target;
    type Stream = XfrMiddlewareStream<
        NextSvc::Future,
        NextSvc::Stream,
        <NextSvc::Stream as Stream>::Item,
    >;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send + Sync>>;

    fn call(
        &self,
        request: Request<RequestOctets, MetaType>,
    ) -> Self::Future {
        let request = request.clone();
        let next_svc = self.next_svc.clone();
        let zones = self.zones.clone();
        let zone_walking_semaphore = self.zone_walking_semaphore.clone();
        let batcher_semaphore = self.batcher_semaphore.clone();
        let xfr_mode = self.xfr_mode;
        Box::pin(async move {
            match Self::preprocess(
                zone_walking_semaphore,
                batcher_semaphore,
                &request,
                zones,
                xfr_mode,
                request.metadata().key(),
            )
            .await
            {
                ControlFlow::Continue(()) => {
                    let request = request.with_new_metadata(());
                    let stream = next_svc.call(request).await;
                    MiddlewareStream::IdentityStream(stream)
                }
                ControlFlow::Break(stream) => stream,
            }
        })
    }
}

//--- Service (without TSIG key name in the request metadata)

impl<RequestOctets, NextSvc, ZL> Service<RequestOctets, ()>
    for XfrMiddlewareSvc<RequestOctets, NextSvc, ZL>
where
    RequestOctets: Octets + Send + Sync + Unpin + 'static,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, ()> + Clone + Send + Sync + 'static,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    NextSvc::Stream: Send + Sync,
    ZL: ZoneLookup + Clone + Sync + Send + 'static,
{
    type Target = NextSvc::Target;
    type Stream = XfrMiddlewareStream<
        NextSvc::Future,
        NextSvc::Stream,
        <NextSvc::Stream as Stream>::Item,
    >;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send + Sync>>;

    fn call(&self, request: Request<RequestOctets, ()>) -> Self::Future {
        let request = request.clone();
        let next_svc = self.next_svc.clone();
        let zones = self.zones.clone();
        let zone_walking_semaphore = self.zone_walking_semaphore.clone();
        let batcher_semaphore = self.batcher_semaphore.clone();
        let xfr_mode = self.xfr_mode;
        Box::pin(async move {
            match Self::preprocess(
                zone_walking_semaphore,
                batcher_semaphore,
                &request,
                zones,
                xfr_mode,
                None,
            )
            .await
            {
                ControlFlow::Continue(()) => {
                    let request = request.with_new_metadata(());
                    let stream = next_svc.call(request).await;
                    MiddlewareStream::IdentityStream(stream)
                }
                ControlFlow::Break(stream) => stream,
            }
        })
    }
}
