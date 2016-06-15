//! A task for a simple, raw DNS query.

use bits::{Class, DName, MessageBuf, Question, RRType};
use resolv::error::Error;
use resolv::tasks::traits::{Progress, Task, TaskRunner};

//------------ Query --------------------------------------------------------

/// A raw DNS query.
///
/// This task will aks the DNS for all resource records associated by the
/// given triple of domain name, resource record type, and class. It will
/// return the raw DNS response as returned by an upstream server in an
/// owned DNS message of type `MessageBuf`. If that message reports no
/// error, it will contain all records in the answer section. The section
/// may be empty, if there is no matching records.
/// 
/// Note, however, that a given DNS node may be an alias. In this case,
/// the answer section will contain one or more CNAME records with the
/// requested class. One such record will be for the requested domain name
/// and contain a different domain name, indicating that the requested node
/// is actually an alias for that new name and the requested class. There
/// may now either be another CNAME records mapping from that name yet
/// again or records of the requested type with that name.
///
/// There may be additional records in the authority and answer sections.
pub struct Query<'a> {
    name: DName<'a>,
    rtype: RRType,
    class: Class,
}

impl<'a> Query<'a> {
    /// Creates a new query from the domain name, record type, and class.
    pub fn new(name: DName<'a>, rtype: RRType, class: Class) -> Self {
        Query { name: name, rtype: rtype, class: class }
    }

    /// Creates a new query in the IN class with the given name and type.
    pub fn new_in(name: DName<'a>, rtype: RRType) -> Self {
        Query::new(name, rtype, Class::IN)
    }
}

impl<'a> Task for Query<'a> {
    type Runner = QueryRunner;

    fn start<F>(self, mut f: F) -> Self::Runner
             where F: FnMut(&DName, RRType, Class) {
        f(&self.name, self.rtype, self.class);
        QueryRunner
    }
}

pub struct QueryRunner;


impl TaskRunner for QueryRunner {
    type Success = MessageBuf;

    fn progress<F>(self, response: MessageBuf, _f: F)
                   -> Progress<Self, Self::Success>
                where F: FnMut(&DName, RRType, Class) {
        Progress::Success(response)
    }

    fn error<'a, F>(self, _question: &Question<'a>, error: Error, _f: F)
                    -> Progress<Self, Self::Success>
             where F: FnMut(&DName, RRType, Class) {
        Progress::Error(error)
    }
}

