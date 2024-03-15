//! Small utilities for building and working with servers.
use std::string::{String, ToString};

use octseq::{Octets, OctetsBuilder};
use tracing::warn;

use crate::base::message_builder::{
    AdditionalBuilder, OptBuilder, PushError, QuestionBuilder,
};
use crate::base::opt::UnknownOptData;
use crate::base::wire::Composer;
use crate::base::Message;
use crate::base::{MessageBuilder, ParsedDname, Rtype, StreamTarget};
use crate::rdata::AllRecordData;

use super::message::Request;
use super::service::{Service, ServiceResult, ServiceResultItem};

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

//------------ service_fn() --------------------------------------------------

/// Helper to simplify making a [`Service`] impl.
///
/// The [`Service`] trait supports a lot of flexibility in its signature and
/// those of its associated types, but this makes implementing it for simple
/// cases quite verbose.
///
/// `service_fn()` enables you to write a slightly simpler function definition
/// that implements the [`Service`] trait than implementing [`Service`]
/// directly.
///
/// # Example
///
/// The example below implements a simple service that returns a DNS NXDOMAIN
/// error response, does not return an error and does not take any custom
/// metadata as input.
///
/// ```
/// // Import the types we need.
/// use std::future::Future;
/// use domain::net::server::prelude::*;
/// use domain::base::iana::Rcode;
///
/// // Define some types to make the example easier to read.
/// type MyMeta = ();
///
/// // Implement the business logic of our service.
/// // Takes the received DNS request and any additional meta data you wish to
/// // provide, and returns one or more future DNS responses.
/// fn my_service(
///     req: Request<Message<Vec<u8>>>,
///     _meta: MyMeta,
/// ) -> ServiceResult<Vec<u8>, Vec<u8>, impl Future<Output = ServiceResultItem<Vec<u8>, Vec<u8>>>> {
///     // For each request create a single response:
///     Ok(Transaction::single(Box::pin(async move {
///         let builder = mk_builder_for_target();
///         let answer = builder.start_answer(req.message(), Rcode::NXDomain)?;
///         Ok(CallResult::new(answer.additional()))
///     })))
/// }
///
/// // Turn my_service() into an actual Service trait impl.
/// let service = service_fn(my_service, MyMeta::default());
/// ```
///
/// Above we see the outline of what we need to do:
/// - Define a function that implements our request handling logic for our
///   service.
/// - Call [`service_fn()`] to wrap it in an actual [`Service`] impl.
///
/// [`Vec<u8>`]: std::vec::Vec<u8>
/// [`CallResult`]: crate::net::server::service::CallResult
/// [`Result::Ok()`]: std::result::Result::Ok
pub fn service_fn<RequestOctets, Target, Future, T, Metadata>(
    msg_handler: T,
    metadata: Metadata,
) -> impl Service<RequestOctets, Target = Target, Future = Future> + Clone
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default + Send + Sync + 'static,
    Future: std::future::Future<Output = ServiceResultItem<RequestOctets, Target>>
        + Send,
    Metadata: Clone,
    T: Fn(
            Request<Message<RequestOctets>>,
            Metadata,
        ) -> ServiceResult<RequestOctets, Target, Future>
        + Clone,
{
    move |msg| msg_handler(msg, metadata.clone())
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
    request: &Request<Message<RequestOctets>>,
) -> QuestionBuilder<StreamTarget<Target>>
where
    RequestOctets: Octets,
    Target: Composer + OctetsBuilder + Default,
{
    let builder = mk_builder_for_target();

    // RFC (1035?) compliance - copy question from request to response.
    let mut builder = builder.question();
    for rr in request.message().question() {
        match rr {
            Ok(rr) => {
                if let Err(err) = builder.push(rr) {
                    warn!("Internal error while copying question RR to the resposne: {err}");
                }
            }
            Err(err) => {
                warn!(
                    "Parse error while copying question RR to the resposne: {err} [RR: {rr:?}]"
                );
            }
        }
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