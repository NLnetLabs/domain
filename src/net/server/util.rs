//! Small utilities for building and working with servers.
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::string::String;
use std::string::ToString;
use std::sync::Arc;

use octseq::FreezeBuilder;
use octseq::Octets;
use octseq::OctetsBuilder;

use crate::base::message_builder::{AdditionalBuilder, PushError};
use crate::base::message_builder::{OptBuilder, QuestionBuilder};
use crate::base::opt::UnknownOptData;
use crate::base::{wire::Composer, Message};
use crate::base::{MessageBuilder, Rtype};
use crate::base::{ParsedDname, StreamTarget};

use super::service::ServiceError;
use super::service::Transaction;
use super::{
    message::ContextAwareMessage,
    service::{Service, ServiceResult, ServiceResultItem},
};
use crate::rdata::AllRecordData;

//----------- mk_builder_for_target() ----------------------------------------

/// Helper for creating a [`MessageBuilder`] for a `Target`.
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

/// Helper to simplify making a [`Service`] impl.
///
/// The [`Service`] trait supports a lot of flexibility in its signature and
/// those of its associated types, but this makes implementing it for simple
/// cases quite verbose.
///
/// `mk_service()` and associated helpers [`MkServiceRequest`],
/// [`MkServiceResult`] and [`mk_builder_for_target()`] enable you to write a
/// simpler function definition that implements the [`Service`] trait than if
/// you were to attempt to impl [`Service`] directly, at the cost of requiring
/// that you [`Box::pin()`] the returned [`Future`].
///
/// # Example
///
/// The example below implements a simple service that returns a DNS NXDOMAIN
/// error response, does not return an error and does not take any custom
/// metadata as input.
///
/// ```
/// // Import the types we need.
/// use domain::net::server::prelude::*;
/// use domain::base::iana::Rcode;
///
/// // Define some types to make the example easier to read.
/// type MyMeta = ();
///
/// // Implement the business logic of our service.
/// fn my_service(
///     req: MkServiceRequest<Vec<u8>>,               // The received DNS request
///     _meta: MyMeta,                                // Any additional data you need
/// ) -> MkServiceResult<Vec<u8>, Vec<u8>> { // The resulting DNS response(s)
///     // For each request create a single response:
///     Ok(Transaction::single(Box::pin(async move {
///         let builder = mk_builder_for_target();
///         let answer = builder.start_answer(req.message(), Rcode::NXDomain)?;
///         Ok(CallResult::new(answer.additional()))
///     })))
/// }
///
/// // Turn my_service() into an actual Service trait impl.
/// let service = mk_service(my_service, MyMeta::default());
/// ```
///
/// Above we see the outline of what we need to do:
/// - Define a function that implements our request handling logic for our service.
/// - Call [`mk_service()`] to wrap it in an actual [`Service`] impl.
///
/// [`Vec<u8>`]: std::vec::Vec<u8>
/// [`CallResult`]: crate::net::server::service::CallResult
/// [`Result::Ok()`]: std::result::Result::Ok
pub fn mk_service<RequestOctets, Target, Single, T, Metadata>(
    msg_handler: T,
    metadata: Metadata,
) -> impl Service<RequestOctets, Target = Target, Single = Single> + Clone
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default + Send + Sync + 'static,
    Single: Future<Output = ServiceResultItem<RequestOctets, Target>> + Send,
    Metadata: Clone,
    T: Fn(
            Arc<ContextAwareMessage<Message<RequestOctets>>>,
            Metadata,
        ) -> ServiceResult<RequestOctets, Target, Single>
        + Clone,
{
    move |msg| msg_handler(msg, metadata.clone())
}

//----------- MkServiceResult ------------------------------------------------

/// The result of a [`Service`] created by [`mk_service()`].
pub type MkServiceResult<RequestOctets, Target> = Result<
    Transaction<
        ServiceResultItem<RequestOctets, Target>,
        Pin<
            Box<
                dyn Future<Output = ServiceResultItem<RequestOctets, Target>>
                    + Send,
            >,
        >,
    >,
    ServiceError,
>;

//----------- MkServiceRequest -------------------------------------------------

/// The input to a [`Service`] created by [`mk_service()`].
pub type MkServiceRequest<RequestOctets> =
    Arc<ContextAwareMessage<Message<RequestOctets>>>;

//----------- MkServiceTarget --------------------------------------------------

/// Helper trait to simplify specifying [`Service`] impl trait bounds.
pub trait MkServiceTarget<Target>:
    Composer + Octets + FreezeBuilder<Octets = Target> + Default
{
}

impl<Target> MkServiceTarget<Target> for Target
where
    Target: Composer + Octets + FreezeBuilder<Octets = Target> + Default,
    Target::AppendError: Debug,
{
}

//----------- to_pcap_text() -------------------------------------------------

/// Create a string of hex encoded bytes representing the given byte sequence.
///
/// The created string is compatible with the Wireshark text2pcap tool and the
/// Wireshark "File -> Import from hex dump" feature.
///
/// When converting/importing, select Ethernet encapsulation with a dummy UDP
/// header with destination port 53. Wireshark should then automatically
/// interpret the bytes as DNS messages.
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

//----------- start_reply ----------------------------------------------------

pub fn start_reply<RequestOctets, Target>(
    request: &ContextAwareMessage<Message<RequestOctets>>,
) -> QuestionBuilder<StreamTarget<Target>>
where
    RequestOctets: Octets,
    Target: Composer + OctetsBuilder + Default,
{
    let builder = mk_builder_for_target();

    // RFC (1035?) compliance - copy question from request to response.
    let mut builder = builder.question();
    for rr in request.message().question() {
        builder.push(rr.unwrap()).unwrap(); // SAFETY
    }

    builder
}

//----------- add_edns_option ------------------------------------------------

// TODO: This is not ideal as it has to copy the current response temporarily
// in the case that the response already has at least one record in the
// additional section. An alternate approach might be something like
// `ComposeReply` based on `ComposeRequest` which would delay response
// building until the complete set of differences to a base response are
// known. Or a completely different builder approach that can edit a partially
// built message.
pub fn add_edns_options<F, Target>(
    response: &mut AdditionalBuilder<StreamTarget<Target>>,
    op: F,
) -> Result<(), PushError>
where
    F: FnOnce(
        &mut OptBuilder<StreamTarget<Target>>,
    ) -> Result<
        (),
        <StreamTarget<Target> as OctetsBuilder>::AppendError,
    >,
    Target: Composer,
{
    if response.counts().arcount() > 0 {
        // Make a copy of the response
        let copied_response = response.as_slice().to_vec();
        let copied_response = Message::from_octets(&copied_response).unwrap();

        if let Some(current_opt) = copied_response.opt() {
            // Discard the current records in the additional section of the
            // response.
            response.rewind();

            // Copy the non-OPT records from the copied response to the
            // current response.
            if let Ok(current_additional) = copied_response.additional() {
                for rr in current_additional.flatten() {
                    if rr.rtype() != Rtype::Opt {
                        if let Ok(Some(rr)) = rr
                            .into_record::<AllRecordData<_, ParsedDname<_>>>()
                        {
                            response.push(rr)?;
                        }
                    }
                }
            }

            // Build a new OPT record in the current response, consisting of
            // the options within the existing OPT record plus the new options
            // that we want to add.
            let res = response.opt(|builder| {
                for opt in
                    current_opt.opt().iter::<UnknownOptData<_>>().flatten()
                {
                    builder.push(&opt)?;
                }
                op(builder)
            });

            return res;
        }
    }

    // No existing OPT record in the additional section so build a new one.
    response.opt(op)
}
