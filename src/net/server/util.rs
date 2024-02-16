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

use crate::base::MessageBuilder;
use crate::base::StreamTarget;
use crate::base::{wire::Composer, Message};

use super::service::ServiceError;
use super::service::Transaction;
use super::{
    message::ContextAwareMessage,
    service::{Service, ServiceResult, ServiceResultItem},
};

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
/// use domain::net::server::prelude::*;
/// use domain::base::iana::Rcode;
///
/// type MyError = ();
/// type MyMeta = ();
///
/// fn my_service(
///     request: MkServiceRequest<Vec<u8>>,
///     _meta: MyMeta,
/// ) -> MkServiceResult<Vec<u8>, MyError> {
///     Ok(Transaction::single(Box::pin(async move {
///         let answer = mk_builder_for_target()
///             .start_answer(&request, Rcode::NXDomain)
///             .unwrap();
///         Ok(CallResult::new(answer.additional()))
///     })))
/// }
///
/// let service = mk_service(my_service, MyMeta::default());
/// ```
/// 
/// Let's look at that step by step:
/// 
/// - `use domain::net::server::prelude::*;` allows you to easily import the
///   various types that you will need.
/// - Neither `type MyError = ();` and `type MyMeta = ();` are strictly needed
///   but make the example more readable.
/// - `fn my_service()` defines the a [`Service`] like helper function.
/// - `let service = mk_service()` wraps `my_service()` in a function that is
///   a compatible match for the [`Service`] trait.
/// 
/// Within `my_service()` we then see, moving from the innermost code
/// outwards:
/// 
/// - `mk_builder_for_target()` is used to create a [`MessageBuilder`]
///   compatible with the [`Vec<u8>`] output type of our function.
/// - [`MessageBuilder::start_answer()`] creates an empty answer corresponding
///   to the given request and having a DNS response code `NXDomain`
///   signalling that the service does not know the domain of the request, if
///   any domain were actually provided in the request.
/// - `Ok(CallResult::new(answer.additional()))` shows the constructed DNS
///   answer section being turned into a single `CallResult` that will be the
///   result of the future (the `async move` block we defined).
/// - `Ok(Transaction::single())` wraps the future into a [`Transaction`]
///   result signalling that this service produces a single DNS response
///   message per DNS request that it is asked to process.
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

//----------- MkServiceResult ------------------------------------------------

/// The result of a [`Service`] created by [`mk_service()`].
pub type MkServiceResult<Target, Error> = Result<
    Transaction<
        ServiceResultItem<Target, Error>,
        Pin<
            Box<dyn Future<Output = ServiceResultItem<Target, Error>> + Send>,
        >,
    >,
    ServiceError<Error>,
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
