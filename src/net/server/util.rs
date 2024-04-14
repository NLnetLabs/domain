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
use super::service::{CallResult, Service, ServiceError, Transaction};
use crate::base::iana::Rcode;

//----------- mk_builder_for_target() ----------------------------------------

/// Helper for creating a [`MessageBuilder`] for a `Target`.
pub fn mk_builder_for_target<Target>() -> MessageBuilder<StreamTarget<Target>>
where
    Target: Composer + Default,
{
    let target = StreamTarget::new(Target::default())
        .map_err(|_| ())
        .expect("Internal error: Unable to create new target.");
    MessageBuilder::from_target(target).expect(
        "Internal error: Unable to convert target to message builder.",
    )
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
/// use std::boxed::Box;
/// use std::future::Future;
/// use std::pin::Pin;
/// use domain::base::iana::Rcode;
/// use domain::base::Message;
/// use domain::net::server::message::Request;
/// use domain::net::server::service::{CallResult, ServiceError, Transaction};
/// use domain::net::server::util::{mk_builder_for_target, service_fn};
///
/// // Define some types to make the example easier to read.
/// type MyMeta = ();
///
/// // Implement the application logic of our service.
/// // Takes the received DNS request and any additional meta data you wish to
/// // provide, and returns one or more future DNS responses.
/// fn my_service(
///     req: Request<Vec<u8>>,
///     _meta: MyMeta,
/// ) -> Result<
///     Transaction<Vec<u8>,
///         Pin<Box<dyn Future<
///             Output = Result<CallResult<Vec<u8>>, ServiceError>
///         >>>,
///     >,
///     ServiceError,
/// > {
///     // For each request create a single response:
///     Ok(Transaction::single(Box::pin(async move {
///         let builder = mk_builder_for_target();
///         let answer = builder.start_answer(req.message(), Rcode::NXDOMAIN)?;
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
/// - Call [`service_fn`] to wrap it in an actual [`Service`] impl.
///
/// [`Vec<u8>`]: std::vec::Vec<u8>
/// [`CallResult`]: crate::net::server::service::CallResult
/// [`Result::Ok`]: std::result::Result::Ok
pub fn service_fn<RequestOctets, Target, Stream, T, Metadata>(
    request_handler: T,
    metadata: Metadata,
) -> impl Service<RequestOctets, Target = Target/*, Stream = Stream */> + Clone
where
    RequestOctets: AsRef<[u8]>,
    Stream: futures::stream::Stream<
        Item = Result<CallResult<Target>, ServiceError>,
    > + Send + Unpin,
    Metadata: Clone,
    T: Fn(Request<RequestOctets>, Metadata) -> Stream + Clone,
{
    move |request| request_handler(request, metadata.clone())
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

/// Create a DNS response message that is a reply to a given request message.
///
/// Copy the request question into a new response and return the builder for
/// further message construction.
///
/// On internal error this function will attempt to set RCODE ServFail in the
/// returned message.
pub fn start_reply<RequestOctets, Target>(
    request: &Request<RequestOctets>,
) -> QuestionBuilder<StreamTarget<Target>>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    let builder = mk_builder_for_target();

    // RFC (1035?) compliance - copy question from request to response.
    let mut abort = false;
    let mut builder = builder.question();
    for rr in request.message().question() {
        match rr {
            Ok(rr) => {
                if let Err(err) = builder.push(rr) {
                    warn!("Internal error while copying question RR to the resposne: {err}");
                    abort = true;
                    break;
                }
            }
            Err(err) => {
                warn!(
                    "Parse error while copying question RR to the resposne: {err} [RR: {rr:?}]"
                );
                abort = true;
                break;
            }
        }
    }

    if abort {
        builder.header_mut().set_rcode(Rcode::SERVFAIL);
    }

    builder
}

//----------- add_edns_option ------------------------------------------------

/// Adds one or more EDNS OPT options to a response.
///
/// If the response already has an OPT record the options will be added to
/// that. Otherwise an OPT record will be created to hold the new options.
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
    // TODO: This is not ideal as it has to copy the current response
    // temporarily in the case that the response already has at least one
    // record in the additional section. An alternate approach might be
    // something like `ComposeReply` based on `ComposeRequest` which would
    // delay response building until the complete set of differences to a base
    // response are known. Or a completely different builder approach that can
    // edit a partially built message.
    if response.counts().arcount() > 0
        && response.as_message().opt().is_some()
    {
        // Make a copy of the response.
        let copied_response = response.as_slice().to_vec();
        let Ok(copied_response) = Message::from_octets(&copied_response)
        else {
            warn!("Internal error: Unable to create message from octets while adding EDNS option");
            return Ok(());
        };

        if let Some(current_opt) = copied_response.opt() {
            // Discard the current records in the additional section of the
            // response.
            response.rewind();

            // Copy the non-OPT records from the copied response to the
            // current response.
            if let Ok(current_additional) = copied_response.additional() {
                for rr in current_additional.flatten() {
                    if rr.rtype() != Rtype::OPT {
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

/// Removes any OPT records present in the response.
pub fn remove_edns_opt_record<Target>(
    response: &mut AdditionalBuilder<StreamTarget<Target>>,
) -> Result<(), PushError>
where
    Target: Composer,
{
    // TODO: This function has the same less than ideal properties as the
    // add_edns_options() function above that it is similar to, ideally we can
    // avoid the need to copy the response.
    if response.counts().arcount() > 0
        && response.as_message().opt().is_some()
    {
        // Make a copy of the response.
        let copied_response = response.as_slice().to_vec();
        let Ok(copied_response) = Message::from_octets(&copied_response)
        else {
            warn!("Internal error: Unable to create message from octets while adding EDNS option");
            return Ok(());
        };

        if copied_response.opt().is_some() {
            // Discard the current records in the additional section of the
            // response.
            response.rewind();

            // Copy the non-OPT records from the copied response to the
            // current response.
            if let Ok(current_additional) = copied_response.additional() {
                for rr in current_additional.flatten() {
                    if rr.rtype() != Rtype::OPT {
                        if let Ok(Some(rr)) = rr
                            .into_record::<AllRecordData<_, ParsedDname<_>>>()
                        {
                            response.push(rr)?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
