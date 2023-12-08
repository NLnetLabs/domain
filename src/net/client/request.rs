//! Traits for request/response transports

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use bytes::Bytes;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

use crate::base::Message;
use crate::net::client::error::Error;

/// Trait for starting a DNS request based on a request composer.
///
/// In the future, the return type of request should become an associated type.
/// However, the use of 'dyn Request' in redundant currently prevents that.
pub trait Request<CR> {
    /// Request function that takes a ComposeRequest type.
    ///
    /// This function is intended to be cancel safe.
    fn request<'a>(
        &'a self,
        request_msg: &'a CR,
    ) -> Pin<Box<dyn Future<Output = RequestResultOutput> + Send + '_>>;
}

/// This type is the actual result type of the future returned by the
/// request function in the Request trait.
type RequestResultOutput = Result<Box<dyn GetResponse + Send>, Error>;

/// Trait for getting the result of a DNS query.
///
/// In the future, the return type of get_response should become an associated
/// type. However, too many uses of 'dyn GetResponse' currently prevent that.
pub trait GetResponse: Debug {
    /// Get the result of a DNS request.
    ///
    /// This function is intended to be cancel safe.
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    >;
}
