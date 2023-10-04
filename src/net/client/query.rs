//! Traits for query transports

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use bytes::Bytes;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
// use std::sync::Arc;

use crate::base::Message;
use crate::net::client::error::Error;

/// Trait for starting a DNS query based on a message.
pub trait QueryMessage<GR: GetResult, Octs> {
    /// Query function that takes a message builder type.
    ///
    /// This function is intended to be cancel safe.
    fn query<'a>(
        &'a self,
        query_msg: &'a Message<Octs>,
    ) -> Pin<Box<dyn Future<Output = Result<GR, Error>> + Send + '_>>;
}

/*
// This trait is replaced with QueryMessage3
/// Trait for starting a DNS query based on a message.
pub trait QueryMessage2<Octs> {
    /// Query function that takes a message builder type.
    ///
    /// This function is intended to be cancel safe.
    fn query<'a>(
        &'a self,
        query_msg: &'a mut MessageBuilder<
            StaticCompressor<StreamTarget<Octs>>,
        >,
    ) -> Pin<Box<dyn Future<Output = QueryResultOutput> + Send + '_>>;
}
*/

/// Trait for starting a DNS query based on a message.
pub trait QueryMessage3<Octs> {
    /// Query function that takes a message type.
    ///
    /// This function is intended to be cancel safe.
    fn query<'a>(
        &'a self,
        query_msg: &'a Message<Octs>,
    ) -> Pin<Box<dyn Future<Output = QueryResultOutput> + Send + '_>>;
}

/// This type is the actual result type of the future returned by the
/// query function in the QueryMessage2 trait.
type QueryResultOutput = Result<Box<dyn GetResult + Send>, Error>;

/// Trait for getting the result of a DNS query.
pub trait GetResult: Debug {
    /// Get the result of a DNS query.
    ///
    /// This function is intended to be cancel safe.
    fn get_result(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    >;
}
