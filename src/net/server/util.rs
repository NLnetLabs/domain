use std::future::Future;
use std::sync::Arc;

use crate::base::{wire::Composer, Message};

use super::traits::{
    message::ContextAwareMessage,
    service::{Service, ServiceResult, ServiceResultItem},
};

//------------ mk_service ----------------------------------------------------

pub fn mk_service<RequestOctets, Target, Error, SingleFut, T, Metadata>(
    msg_handler: T,
    metadata: Metadata,
) -> impl Service<RequestOctets, Error = Error, Target = Target, Single = SingleFut>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default + Send + Sync + 'static,
    Error: Send + Sync + 'static,
    SingleFut: Future<Output = ServiceResultItem<Target, Error>> + Send,
    Metadata: Clone,
    T: Fn(
        Arc<ContextAwareMessage<Message<RequestOctets>>>,
        Metadata,
    ) -> ServiceResult<Target, Error, SingleFut>,
{
    move |msg| msg_handler(msg, metadata.clone())
}
