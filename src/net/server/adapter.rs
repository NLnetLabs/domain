//! Service adapters.
//!
//! This module defines three adapters for [SingleService]. The first,
//! [ClientTransportToSingleService] implements [SingleService] for a
//! client transport ([SendRequest]).
//! The second one, [BoxClientTransportToSingleService],
//! implements [Service] for a boxed trait object of [SendRequest].
//! The third one, [SingleServiceToService] implements [Service] for
//! [SingleService].

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use super::message::Request;
use super::service::{CallResult, Service, ServiceError, ServiceResult};
use super::single_service::{ComposeReply, SingleService};
use crate::dep::octseq::Octets;
use crate::net::client::request::{Error, RequestMessage, SendRequest};
use futures::stream::{once, Once};
use std::boxed::Box;
use std::fmt::Debug;
use std::future::{ready, Future, Ready};
use std::marker::PhantomData;
use std::pin::Pin;
use std::vec::Vec;

/// Provide a [Service] trait for an object that implements [SingleService].
pub struct SingleServiceToService<RequestOcts, SVC, CR> {
    /// Service that is wrapped by this object.
    service: SVC,

    /// Phantom field for RequestOcts and CR.
    _phantom: PhantomData<(RequestOcts, CR)>,
}

impl<RequestOcts, SVC, CR> SingleServiceToService<RequestOcts, SVC, CR> {
    /// Create a new [SingleServiceToService] object.
    pub fn new(service: SVC) -> Self {
        Self {
            service,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOcts, SVC, CR> Service<RequestOcts>
    for SingleServiceToService<RequestOcts, SVC, CR>
where
    RequestOcts: Octets + Send + Sync + Unpin,
    SVC: SingleService<RequestOcts, CR>,
    CR: ComposeReply + 'static,
{
    type Target = Vec<u8>;
    type Stream = Once<Ready<ServiceResult<Self::Target>>>;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send>>;

    fn call(&self, request: Request<RequestOcts>) -> Self::Future {
        let fut = self.service.call(request);
        let fut = async move {
            let reply = match fut.await {
                Ok(reply) => reply,
                Err(_) => {
                    // Every error gets mapped to InternalError.
                    // Should we add an EDE here?
                    return once(ready(Err(ServiceError::InternalError)));
                }
            };
            let abs = match reply.additional_builder_stream_target() {
                Ok(reply) => reply,
                Err(_) => {
                    // Every error gets mapped to InternalError.
                    // There is probably not much we could do here.
                    // The error results from a bad reply message.
                    return once(ready(Err(ServiceError::InternalError)));
                }
            };
            once(ready(Ok(CallResult::new(abs))))
        };
        Box::pin(fut)
    }
}

/// Provide a [SingleService] trait for an object that implements the
/// [SendRequest] trait.
pub struct ClientTransportToSingleService<SR, RequestOcts>
where
    RequestOcts: AsRef<[u8]>,
    SR: SendRequest<RequestMessage<RequestOcts>>,
{
    /// The client transport to use.
    conn: SR,

    /// Phantom data for RequestOcts.
    _phantom: PhantomData<RequestOcts>,
}

impl<SR, RequestOcts> ClientTransportToSingleService<SR, RequestOcts>
where
    RequestOcts: AsRef<[u8]>,
    SR: SendRequest<RequestMessage<RequestOcts>>,
{
    /// Create a new [ClientTransportToSingleService] object.
    pub fn new(conn: SR) -> Self {
        Self {
            conn,
            _phantom: PhantomData,
        }
    }
}

impl<SR, RequestOcts, CR> SingleService<RequestOcts, CR>
    for ClientTransportToSingleService<SR, RequestOcts>
where
    RequestOcts: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync,
    SR: SendRequest<RequestMessage<RequestOcts>> + Sync,
    CR: ComposeReply + Send + Sync + 'static,
{
    fn call(
        &self,
        request: Request<RequestOcts>,
    ) -> Pin<Box<dyn Future<Output = Result<CR, Error>> + Send + Sync>>
    where
        RequestOcts: AsRef<[u8]>,
    {
        let req = match request.try_into() {
            Ok(req) => req,
            Err(e) => return Box::pin(ready(Err(e))),
        };
        let mut gr = self.conn.send_request(req);
        let fut = async move {
            let msg = gr.get_response().await?;
            Ok(CR::from_message(&msg)?)
        };
        Box::pin(fut)
    }
}

/// Implement the [SingleService] trait for a boxed [SendRequest] trait object.
pub struct BoxClientTransportToSingleService<RequestOcts>
where
    RequestOcts: AsRef<[u8]>,
{
    /// The client transport to use.
    conn: Box<dyn SendRequest<RequestMessage<RequestOcts>> + Send + Sync>,

    /// Phantom data for RequestOcts.
    _phantom: PhantomData<RequestOcts>,
}

impl<RequestOcts> BoxClientTransportToSingleService<RequestOcts>
where
    RequestOcts: AsRef<[u8]>,
{
    /// Create a new [BoxClientTransportToSingleService] object.
    pub fn new(
        conn: Box<dyn SendRequest<RequestMessage<RequestOcts>> + Send + Sync>,
    ) -> Self {
        Self {
            conn,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOcts, CR> SingleService<RequestOcts, CR>
    for BoxClientTransportToSingleService<RequestOcts>
where
    RequestOcts: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync,
    CR: ComposeReply + Send + Sync + 'static,
{
    fn call(
        &self,
        request: Request<RequestOcts>,
    ) -> Pin<Box<dyn Future<Output = Result<CR, Error>> + Send + Sync>>
    where
        RequestOcts: AsRef<[u8]>,
    {
        let req = match request.try_into() {
            Ok(req) => req,
            Err(e) => return Box::pin(ready(Err(e))),
        };
        let mut gr = self.conn.send_request(req);
        let fut = async move {
            let msg = gr.get_response().await?;
            Ok(CR::from_message(&msg)?)
        };
        Box::pin(fut)
    }
}
