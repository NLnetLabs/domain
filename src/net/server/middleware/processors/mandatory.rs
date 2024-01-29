use std::fmt::Debug;

use octseq::{FreezeBuilder, Octets, OctetsBuilder};

use crate::{
    base::{
        message_builder::AdditionalBuilder, wire::Composer, Message,
        MessageBuilder, StreamTarget,
    },
    net::server::{
        middleware::processor::{
            MiddlewareProcessor, PreprocessingError, PreprocessingOk,
        },
        ContextAwareMessage,
    },
};

#[derive(Default)]
pub struct MandatoryMiddlewareProcesor;

impl MandatoryMiddlewareProcesor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<Target> MiddlewareProcessor<Target> for MandatoryMiddlewareProcesor
where
    Target: Composer + Octets + FreezeBuilder<Octets = Target>,
    <Target as OctetsBuilder>::AppendError: Debug,
{
    fn preprocess(
        &self,
        request: ContextAwareMessage<Message<Target>>,
        builder: MessageBuilder<StreamTarget<Target>>,
    ) -> Result<PreprocessingOk<Target>, PreprocessingError<Target>> {
        Ok((request, builder))
    }

    fn postprocess(
        &self,
        request: &ContextAwareMessage<Message<Target>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
        // 4.1.1: Header section format
        eprintln!("post-process mandatory");

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
