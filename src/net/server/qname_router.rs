//! This module provides an example query router using the Qname field.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use super::message::Request;
use super::single_service::SingleService;
use crate::dep::octseq::Octets;
use crate::net::client::request::Error;
use core::any::Any;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::vec::Vec;

/// A service that routes requests to other services based on the Qname in the
/// request.
pub struct QnameRouter<RequestOcts: Octets + Send + Sync, CR> {
    /// List of names and services for routing requests.
    list: Vec<Element<RequestOcts, CR>>,
}

/// Element in the name space for the Qname router.
struct Element<RequestOcts: Octets + Send + Sync, CR> {
    /// Name to match for this element.
    // name: Name<NameOcts>,
    callback: Box<
        dyn Fn(&Request<RequestOcts>, &Box<dyn Any + Send + Sync>) -> usize
            + Send
            + Sync,
    >,

    data: Box<dyn Any + Send + Sync>,

    /// Service to call for this element.
    service: Box<dyn SingleService<RequestOcts, CR> + Send + Sync>,
}

impl<RequestOcts: Octets + Send + Sync, CR> QnameRouter<RequestOcts, CR> {
    /// Create a new empty router.
    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    /// Add a name and service to the router.
    pub fn add<SVC>(
        &mut self,
        callback: Box<
            dyn Fn(
                    &Request<RequestOcts>,
                    &Box<dyn Any + Send + Sync>,
                ) -> usize
                + Send
                + Sync,
        >,
        data: Box<dyn Any + Send + Sync>,
        service: SVC,
    ) where
        SVC: SingleService<RequestOcts, CR> + Send + Sync + 'static,
    {
        let el = Element {
            callback,
            data,
            service: Box::new(service),
        };
        self.list.push(el);
    }
}

impl<RequestOcts: Octets + Send + Sync, CR> Default
    for QnameRouter<RequestOcts, CR>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<RequestOcts: Octets + Send + Sync + Unpin, CR>
    SingleService<RequestOcts, CR> for QnameRouter<RequestOcts, CR>
{
    fn call(
        &self,
        request: Request<RequestOcts>,
    ) -> Pin<Box<dyn Future<Output = Result<CR, Error>> + Send + Sync>>
    where
        RequestOcts: AsRef<[u8]> + Octets,
    {
        // let question = request
        //     .message()
        //     .question()
        //     .into_iter()
        //     .next()
        //     .unwrap()
        //     .unwrap();
        // let name = question.qname();
        // self.list
        //     .iter()
        //     .filter(|l| name.ends_with(&l.name))
        //     .max_by_key(|l| l.name.label_count())
        //     .unwrap()
        //     .service
        //     .call(request.clone())
        self.list
            .iter()
            .filter_map(|el| Some((el, (el.callback)(&request, &el.data))))
            .max_by_key(|(_el, score)| *score)
            .unwrap()
            .0
            .service
            .call(request.clone())
    }
}
