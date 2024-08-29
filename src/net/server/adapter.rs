// adapters

use super::message::{Request, RequestNG};
use super::service::{CallResult, Service, ServiceResult, };
use super::single_service::{ComposeReply, SingleService};
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
//use std::future::Ready;
use crate::dep::octseq::Octets;
use crate::net::client::request::{Error, RequestMessage};
use crate::net::client::request::SendRequest;
//use futures::Stream;
use futures::stream::Once;
use futures::stream::once;
use std::future::Ready;
use std::future::ready;
use std::pin::Pin;
use std::vec::Vec;

pub struct SingleServiceToService<SVC, CR> {
    service: SVC,
    phantom: PhantomData<CR>,
}

impl<SVC, CR> SingleServiceToService<SVC, CR> {
    pub fn new(service: SVC) -> Self {
        Self {
            service,
            phantom: PhantomData,
        }
    }
}

impl<SVC, CR> Service for SingleServiceToService<SVC, CR>
where
    SVC: SingleService<Vec<u8>, CR>,
    CR: ComposeReply + 'static,
{
    type Target = Vec<u8>;
    type Stream = Once<Ready<ServiceResult<Self::Target>>>;
    type Future = Pin<
        Box<
            dyn Future<Output = Self::Stream, > + Send,
        >,
    >;

    fn call(
        &self,
        request: Request<Vec<u8>>,
    ) -> Self::Future {
        let req = RequestNG::from_request(request);
        let fut = self.service.call(req);
        let fut = async move {
            let reply = fut.await.unwrap();
            let abs = reply.additional_builder_stream_target();
            once(ready(Ok(CallResult::new(abs))))
        };
        Box::pin(fut)
    }
}

pub struct ClientTransportToSrService<SR, RequestOcts>
where
    RequestOcts: AsRef<[u8]>,
    SR: SendRequest<RequestMessage<RequestOcts>>,
{
    conn: SR,
    _phantom: PhantomData<RequestOcts>,
}

impl<SR, RequestOcts> ClientTransportToSrService<SR, RequestOcts>
where
    RequestOcts: AsRef<[u8]>,
    SR: SendRequest<RequestMessage<RequestOcts>>,
{
    pub fn new(conn: SR) -> Self {
        Self {
            conn,
            _phantom: PhantomData,
        }
    }
}

impl<SR, RequestOcts, CR> SingleService<RequestOcts, CR>
    for ClientTransportToSrService<SR, RequestOcts>
where
    RequestOcts: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync,
    SR: SendRequest<RequestMessage<RequestOcts>> + Sync,
    CR: ComposeReply + Send + Sync + 'static,
{
    type Target = Vec<u8>;

    fn call(
        &self,
        request: RequestNG<RequestOcts>,
    ) -> Pin<Box<dyn Future<Output = Result<CR, Error>> + Send + Sync>>
    where
        RequestOcts: AsRef<[u8]>,
    {
        let req = match request.to_request_message() {
	    Ok(req) => req,
	    Err(e) => return Box::pin(ready(Err(e))),
	};
        let mut gr = self.conn.send_request(req);
        let fut = async move {
            let msg = gr.get_response().await.unwrap();
            Ok(CR::from_message(&msg))
        };
        Box::pin(fut)
    }
}
