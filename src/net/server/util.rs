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
use crate::base::{MessageBuilder, ParsedName, Rtype, StreamTarget};
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
pub fn service_fn<RequestOctets, Target, Future, T, Metadata>(
    request_handler: T,
    metadata: Metadata,
) -> impl Service<RequestOctets, Target = Target, Future = Future> + Clone
where
    RequestOctets: AsRef<[u8]>,
    Future: std::future::Future<
        Output = Result<CallResult<Target>, ServiceError>,
    >,
    Metadata: Clone,
    T: Fn(
            Request<RequestOctets>,
            Metadata,
        ) -> Result<Transaction<Target, Future>, ServiceError>
        + Clone,
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
                            .into_record::<AllRecordData<_, ParsedName<_>>>()
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
                            .into_record::<AllRecordData<_, ParsedName<_>>>()
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::time::Instant;

    use crate::base::{Message, MessageBuilder, Name, Rtype, StreamTarget};
    use crate::net::server::message::{Request, UdpTransportContext};

    use super::start_reply;
    use crate::base::iana::{OptRcode, Rcode};
    use crate::base::message_builder::AdditionalBuilder;
    use crate::base::opt::UnknownOptData;
    use crate::base::wire::Composer;
    use crate::net::server::util::{
        add_edns_options, remove_edns_opt_record,
    };
    use std::vec::Vec;

    #[test]
    fn test_add_edns_option() {
        // Given a dummy DNS query.
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        query.push((Name::<Bytes>::root(), Rtype::A)).unwrap();
        let msg = query.into_message();

        // Package it into a received request.
        let client_ip = "127.0.0.1:12345".parse().unwrap();
        let sent_at = Instant::now();
        let ctx = UdpTransportContext::default();
        let request = Request::new(client_ip, sent_at, msg, ctx.into());

        // Create a dummy DNS reply which does not yet have an OPT record.
        let reply = start_reply::<_, Vec<u8>>(&request);
        assert_eq!(reply.counts().arcount(), 0);
        assert_eq!(reply.header().rcode(), Rcode::NOERROR);

        // Add an OPT record to the reply.
        let mut reply = reply.additional();
        reply
            .opt(|builder| {
                builder.set_rcode(OptRcode::BADCOOKIE);
                builder.set_udp_payload_size(123);
                Ok(())
            })
            .unwrap();
        assert_eq!(reply.counts().arcount(), 1);

        // When an OPT record exists the RCODE of the DNS message is extended
        // from 4-bits to 12-bits, combining the original 4-bit RCODE in the
        // DNS message header with an additional 8-bits in the OPT record
        // header. This causes the main DNS header RCODE value to seem wrong
        // if inspected in isolation. We set the RCODE to BADCOOKIE but that
        // has value 23 which exceeds the 4-bit range maximum value and so is
        // encoded as a full 12-bit RCODE. 23 in binary is 0001_0111 which as
        // you can see causes the lower 4-bits to have value 0111 which is 7.
        let expected_rcode = Rcode::checked_from_int(0b0111).unwrap();
        assert_eq!(reply.header().rcode(), expected_rcode);

        // Note: We can't test the upper 8-bits of the extended RCODE as there
        // is no way to access the OPT record header via a message builder. We
        // can however serialize the message and deserialize it again and
        // check it via the Message interface.
        let response = assert_opt(
            reply.clone(),
            expected_rcode,
            Some(OptRcode::BADCOOKIE),
        );

        // And that it has no EDNS options.
        let opt = response.opt().unwrap();
        let options = opt.opt();
        assert_eq!(options.len(), 0);

        // Now add an EDNS option to the OPT record.
        add_edns_options(&mut reply, |builder| builder.padding(123)).unwrap();

        // And verify that the OPT record still exists as expected.
        let response = assert_opt(
            reply.clone(),
            expected_rcode,
            Some(OptRcode::BADCOOKIE),
        );

        // And that it has a single EDNS option.
        let opt = response.opt().unwrap();
        let options = opt.opt();
        assert_eq!(options.iter::<UnknownOptData<_>>().count(), 1);

        // Now add another EDNS option to the OPT record (duplicates are allowed
        // by RFC 6891).
        add_edns_options(&mut reply, |builder| builder.padding(123)).unwrap();

        // And verify that the OPT record still exists as expected.
        let response = assert_opt(
            reply.clone(),
            expected_rcode,
            Some(OptRcode::BADCOOKIE),
        );

        // And that it has a single EDNS option.
        let opt = response.opt().unwrap();
        let options = opt.opt();
        assert_eq!(options.iter::<UnknownOptData<_>>().count(), 2);
    }

    #[test]
    fn test_remove_edns_opt_record() {
        // Given a dummy DNS query.
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        query.push((Name::<Bytes>::root(), Rtype::A)).unwrap();
        let msg = query.into_message();

        // Package it into a received request.
        let client_ip = "127.0.0.1:12345".parse().unwrap();
        let sent_at = Instant::now();
        let ctx = UdpTransportContext::default();
        let request = Request::new(client_ip, sent_at, msg, ctx.into());

        // Create a dummy DNS reply which does not yet have an OPT record.
        let reply = start_reply::<_, Vec<u8>>(&request);
        assert_eq!(reply.counts().arcount(), 0);

        // Add an OPT record to the reply.
        let mut reply = reply.additional();
        reply.opt(|builder| builder.padding(32)).unwrap();
        assert_eq!(reply.counts().arcount(), 1);

        // Note: We can't test that the OPT record exists or inspect its properties
        // when using a MessageBuilder, but we can if we serialize it and deserialize
        // it again as a Message.
        assert_opt(reply.clone(), Rcode::NOERROR, Some(OptRcode::NOERROR));

        // Now remove the OPT record from the saved reply.
        remove_edns_opt_record(&mut reply).unwrap();

        // And verify that the OPT record no longer exists when serialized and
        // deserialized again.
        assert_opt(reply.clone(), Rcode::NOERROR, None);
    }

    //------------ Helper functions ------------------------------------------

    fn assert_opt<Target: Composer>(
        reply: AdditionalBuilder<StreamTarget<Target>>,
        expected_rcode: Rcode,
        expected_opt_rcode: Option<OptRcode>,
    ) -> Message<Vec<u8>> {
        // Serialize the reply to wire format so that we can test that the OPT
        // record was really added to a finally constructed DNS message and
        // has the expected RCODE and OPT extended RCODE values.
        let response = reply.finish();
        let response_bytes = response.as_dgram_slice().to_vec();
        let response = Message::from_octets(response_bytes).unwrap();

        assert_eq!(response.header().rcode(), expected_rcode);
        match expected_opt_rcode {
            Some(opt_rcode) => {
                assert_eq!(response.header_counts().arcount(), 1);
                assert!(response.opt().is_some());
                assert_eq!(response.opt_rcode(), opt_rcode);
            }

            None => {
                assert_eq!(response.header_counts().arcount(), 0);
                assert!(response.opt().is_none());
            }
        }

        response
    }
}
