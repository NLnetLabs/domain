// Qname Router

use super::message::RequestNG;
use super::single_service::SingleService;
use crate::base::Name;
use crate::base::ToName;
use crate::dep::octseq::EmptyBuilder;
use crate::dep::octseq::FromBuilder;
use crate::dep::octseq::Octets;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::vec::Vec;

pub struct QnameRouter<Octs, RequestOcts, CR> {
    list: Vec<Element<Octs, RequestOcts, CR>>,
}

struct Element<NameOcts, RequestOcts, CR> {
    name: Name<NameOcts>,
    service: Box<
        dyn SingleService<RequestOcts, CR, Target = Vec<u8>> + Send + Sync,
    >,
}

impl<Octs, RequestOcts, CR> QnameRouter<Octs, RequestOcts, CR> {
    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    pub fn add<TN, SVC>(&mut self, name: TN, service: SVC)
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder,
        TN: ToName,
        SVC: SingleService<RequestOcts, CR, Target = Vec<u8>>
            + Send
            + Sync
            + 'static,
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
    type Target = ();

    fn call(
        &self,
        request: RequestNG<RequestOcts>,
    ) -> Pin<Box<dyn Future<Output = Result<CR, ()>> + Send + Sync>>
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
