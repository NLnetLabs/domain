/// Common service invoking logic for network servers.
///
/// Used by [`stream::Connection`][net::server::stream::Connection] and
/// [`dgram::Dgram`][net::server::dgram::Dgram].
use core::clone::Clone;
use core::default::Default;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::boxed::Box;

use futures_util::StreamExt;
use octseq::Octets;
use tracing::trace;

use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};

use super::message::Request;
use super::service::{Service, ServiceFeedback, ServiceResult};
use super::util::mk_error_response;

//------------ InvokerStatus --------------------------------------------------

/// The current status of the service invoker.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InvokerStatus {
    /// Processing independent responses.
    Normal,

    /// Processing related responses.
    InTransaction,

    /// No more responses to the current request will be processed.
    Aborting,
}

//------------ ServiceInvoker -------------------------------------------------

/// Dispatch requests to a [`Service`] and do common response processing.
///
/// Response streams will be split into individual responses and passed to the
/// trait implementer for writing back to the network.
///
/// If the [`Service`] impl returns a [`ServiceError`] a corresponding DNS
/// error response will be created and no further responses from the service
/// for the current request will be processed and the service response stream
/// will be dropped.
///
/// Also handles [`ServiceFeedback`] by invoking fn impls on the trait
/// implementing type.
pub trait ServiceInvoker<RequestOctets, Svc, EnqueueMeta>
where
    Svc: Service<RequestOctets> + Send + Sync + 'static,
    Svc::Target: Composer + Default,
    RequestOctets: Octets + Send + Sync + 'static,
    EnqueueMeta: Send + Sync + 'static,
{
    /// Dispatch a request and process the responses.
    ///
    /// Dispatches the given request to the given [`Service`] impl and
    /// processes the stream of resulting responses, passing them to the trait
    /// impl'd [`enqueue_response`] function with the provided metadata for
    /// writing back to the network. until no more responses exist or the
    /// trait impl'd [`status`] function reports that the state is
    /// [`InvokerStatus::Aborting`].
    ///
    /// On [`ServiceFeedback::Reconfigure`] passes the new configuration data
    /// to the trait impl'd [`reconfugure`] function.
    fn dispatch(
        &mut self,
        request: Request<RequestOctets>,
        svc: Svc,
        enqueue_meta: EnqueueMeta,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>
    where
        Self: Send + Sync,
        Svc::Target: Send,
        Svc::Stream: Send,
        Svc::Future: Send,
    {
        Box::pin(async move {
            let req_msg = request.message().clone();
            let request_id = request.message().header().id();

            // Dispatch the request to the service for processing.
            trace!("Calling service for request id {request_id}");
            let mut stream = svc.call(request).await;

            // Handle the resulting stream of responses, most likely just one as
            // only XFR requests potentially result in multiple responses.
            trace!(
                "Awaiting service call results for request id {request_id}"
            );
            while let Some(item) = stream.next().await {
                trace!(
                    "Processing service call result for request id {request_id}"
                );

                let response =
                    self.process_response_stream_item(item, &req_msg);

                if let Some(response) = response {
                    self.enqueue_response(response, &enqueue_meta).await;
                }

                if matches!(self.status(), InvokerStatus::Aborting) {
                    trace!("Aborting response stream processing for request id {request_id}");
                    break;
                }
            }
            trace!("Finished processing service call results for request id {request_id}");
        })
    }

    /// Processing a single response stream item.
    ///
    /// Calls [`process_feedback`] if necessary. Extracts any response for
    /// further processing by the caller.
    ///
    /// On [`ServiceError`] calls the trait impl'd [`set_status`] function
    /// with `InvokerStatus::Aborting` and returns a generated error response
    /// instead of the response from the service.
    fn process_response_stream_item(
        &mut self,
        stream_item: ServiceResult<Svc::Target>,
        req_msg: &Message<RequestOctets>,
    ) -> Option<AdditionalBuilder<StreamTarget<Svc::Target>>> {
        match stream_item {
            Ok(call_result) => {
                let (response, feedback) = call_result.into_inner();
                if let Some(feedback) = feedback {
                    self.process_feedback(feedback);
                }
                response
            }

            Err(err) => {
                self.set_status(InvokerStatus::Aborting);
                Some(mk_error_response(req_msg, err.rcode().into()))
            }
        }
    }

    //// Acts on [`ServiceFeedback`] received from the [`Service`].
    ///
    /// Calls the trait impl'd [`reconfigure`] on
    /// [`ServiceFeedback::Reconfigure`].
    ///
    /// Calls the trait impl'd [`set_status`] on
    /// [`ServiceFeedback::BeginTransaction`] with
    /// [`InvokerStatus::InTransaction`].
    ///
    /// Calls the trait impl'd [`set_status`] on
    /// [`ServiceFeedback::EndTransaction`] with [`InvokerStatus::Normal`].
    fn process_feedback(&mut self, feedback: ServiceFeedback) {
        match feedback {
            ServiceFeedback::Reconfigure { idle_timeout } => {
                self.reconfigure(idle_timeout);
            }

            ServiceFeedback::BeginTransaction => {
                self.set_status(InvokerStatus::InTransaction);
            }

            ServiceFeedback::EndTransaction => {
                self.set_status(InvokerStatus::Normal);
            }
        }
    }

    /// Returns the current status of the service invoker.
    fn status(&self) -> InvokerStatus;

    /// Sets the status of the service invoker to the given status.
    fn set_status(&mut self, status: InvokerStatus);

    /// Reconfigures the network server with new settings.
    fn reconfigure(&self, idle_timeout: Option<Duration>);

    /// Enqueues a response for writing back to the client.
    fn enqueue_response<'a>(
        &'a self,
        response: AdditionalBuilder<StreamTarget<Svc::Target>>,
        meta: &'a EnqueueMeta,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
