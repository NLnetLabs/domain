use crate::{
    base::{
        message_builder::AdditionalBuilder, wire::Composer, Message,
        StreamTarget,
    },
    net::server::{
        middleware::processor::MiddlewareProcessor,
        traits::message::ContextAwareMessage,
    },
};
use core::ops::ControlFlow;

#[derive(Default)]
pub struct MandatoryMiddlewareProcesor;

impl MandatoryMiddlewareProcesor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<RequestOctets, Target> MiddlewareProcessor<RequestOctets, Target>
    for MandatoryMiddlewareProcesor
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    fn preprocess(
        &self,
        _request: &mut ContextAwareMessage<Message<RequestOctets>>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
        ControlFlow::Continue(())
    }

    fn postprocess(
        &self,
        request: &ContextAwareMessage<Message<RequestOctets>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
        // 4.1.1: Header section format

        // ID      A 16 bit identifier assigned by the program that
        //         generates any kind of query.  This identifier is copied
        //         the corresponding reply and can be used by the requester
        //         to match up replies to outstanding queries.
        response.header_mut().set_id(request.header().id());

        // QR      A one bit field that specifies whether this message is a
        //         query (0), or a response (1).
        response.header_mut().set_qr(true);
    }
}
