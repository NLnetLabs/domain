//! This module provides an example query router using the Qname field.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use super::message::RequestNG;
use super::single_service::SingleService;
use crate::base::{Name, ToName};
use crate::dep::octseq::{EmptyBuilder, FromBuilder, Octets};
use crate::net::client::request::Error;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::vec::Vec;

/// A service that routes requests to other services based on the Qname in the
/// request.
pub struct QnameRouter<Octs, RequestOcts, CR> {
    /// List of names and services for routing requests.
    list: Vec<Element<Octs, RequestOcts, CR>>,
}

/// Element in the name space for the Qname router.
struct Element<NameOcts, RequestOcts, CR> {
    /// Name to match for this element.
    name: Name<NameOcts>,

    /// Service to call for this element.
    service: Box<dyn SingleService<RequestOcts, CR> + Send + Sync>,
}

impl<Octs, RequestOcts, CR> QnameRouter<Octs, RequestOcts, CR> {
    /// Create a new empty router.
    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    /// Add a name and service to the router.
    pub fn add<TN, SVC>(&mut self, name: TN, service: SVC)
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder,
        TN: ToName,
        SVC: SingleService<RequestOcts, CR> + Send + Sync + 'static,
    {
        let el = Element {
            name: name.try_to_name().ok().unwrap(),
            service: Box::new(service),
        };
        self.list.push(el);
    }
}

impl<Octs, RequestOcts, CR> Default for QnameRouter<Octs, RequestOcts, CR> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Octs, RequestOcts, CR> SingleService<RequestOcts, CR>
    for QnameRouter<Octs, RequestOcts, CR>
where
    Octs: AsRef<[u8]>,
{
    fn call(
        &self,
        request: RequestNG<RequestOcts>,
    ) -> Pin<Box<dyn Future<Output = Result<CR, Error>> + Send + Sync>>
    where
        RequestOcts: AsRef<[u8]> + Octets,
    {
        let question = request
            .message()
            .question()
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        let name = question.qname();
        self.list
            .iter()
            .filter(|l| name.ends_with(&l.name))
            .max_by_key(|l| l.name.label_count())
            .unwrap()
            .service
            .call(request.clone())
    }
}
