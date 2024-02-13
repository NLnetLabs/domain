use std::future::Future;
use std::string::String;
use std::string::ToString;
use std::sync::Arc;

use octseq::OctetsBuilder;

use crate::base::MessageBuilder;
use crate::base::StreamTarget;
use crate::base::{wire::Composer, Message};

use super::traits::{
    message::ContextAwareMessage,
    service::{Service, ServiceResult, ServiceResultItem},
};

//----------- mk_builder_for_target() ----------------------------------------

pub fn mk_builder_for_target<Target>() -> MessageBuilder<StreamTarget<Target>>
where
    Target: Composer + OctetsBuilder + Default,
{
    let target = StreamTarget::new(Target::default())
        .map_err(|_| ())
        .unwrap(); // SAFETY
    MessageBuilder::from_target(target).unwrap() // SAFETY
}

//------------ mk_service() --------------------------------------------------

pub fn mk_service<RequestOctets, Target, Error, Single, T, Metadata>(
    msg_handler: T,
    metadata: Metadata,
) -> impl Service<RequestOctets, Error = Error, Target = Target, Single = Single>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default + Send + Sync + 'static,
    Error: Send + Sync + 'static,
    Single: Future<Output = ServiceResultItem<Target, Error>> + Send,
    Metadata: Clone,
    T: Fn(
        Arc<ContextAwareMessage<Message<RequestOctets>>>,
        Metadata,
    ) -> ServiceResult<Target, Error, Single>,
{
    move |msg| msg_handler(msg, metadata.clone())
}

//----------- to_pcap_text() -------------------------------------------------

pub(crate) fn to_pcap_text<T: AsRef<[u8]>>(
    bytes: T,
    num_bytes: usize,
) -> String {
    let mut formatted = "000000".to_string();
    let hex_encoded = hex::encode(&bytes.as_ref()[..num_bytes]);
    let mut chars = hex_encoded.chars();
    loop {
        match (chars.next(), chars.next()) {
            (None, None) => break,
            (Some(a), Some(b)) => {
                formatted.push(' ');
                formatted.push(a);
                formatted.push(b);
            }
            _ => unreachable!(),
        }
    }
    formatted
}
