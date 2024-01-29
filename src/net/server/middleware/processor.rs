use crate::{
    base::{
        message_builder::AdditionalBuilder, wire::Composer, Message,
        MessageBuilder, StreamTarget,
    },
    net::server::ContextAwareMessage,
};

pub type PreprocessingOk<Target> = (
    ContextAwareMessage<Message<Target>>,
    MessageBuilder<StreamTarget<Target>>,
);

pub type PreprocessingError<Target> = (
    ContextAwareMessage<Message<Target>>,
    AdditionalBuilder<StreamTarget<Target>>,
);

/// A processing stage applied to incoming and outgoing messages.
///
/// See [`MiddlewareChain`] for more information.
pub trait MiddlewareProcessor<Target>
where
    Target: Composer,
{
    /// Apply middleware pre-processing rules to a request.
    fn preprocess(
        &self,
        request: ContextAwareMessage<Message<Target>>,
        builder: MessageBuilder<StreamTarget<Target>>,
    ) -> Result<PreprocessingOk<Target>, PreprocessingError<Target>>;

    /// Apply middleware post-processing rules to a response.
    fn postprocess(
        &self,
        request: &ContextAwareMessage<Message<Target>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    );
}
