/// Tasks for looking up host addresses.

use std::net::IpAddr;
use std::slice;
use bits::{AsDName, DName, DNameBuf, DNameSlice, MessageBuf, ParseResult,
           Question, RecordData};
use iana::{Class, RRType};
use rdata::{A, AAAA};
use resolv::conf::ResolvConf;
use resolv::tasks::traits::{Progress, Task, TaskRunner};
use resolv::error::{Error, Result};


//------------ LookupHost ---------------------------------------------------

/// Looks up all IP addresses for the given host.
///
/// This task does a DNS query for A and AAAA records of the domain name
/// given to the `LookupHost::new()` function. This differs from the usual
/// address lookup function such as POSIX’s `gethostbyname()`. The task
/// does not consider the hosts file nor does it care about the search
/// list. See `SearchHost` for a task implementing that functionality.
pub struct LookupHost<'a> {
    name: DName<'a>
}

impl<'a> LookupHost<'a> {
    pub fn new(name: DName<'a>) -> Self {
        LookupHost { name: name }
    }
}

impl<'a> Task for LookupHost<'a> {
    type Runner = LookupHostRunner;

    fn start<F>(self, mut f: F) -> Self::Runner
             where F: FnMut(&DName, RRType, Class) {
        {
            f(&self.name, RRType::A, Class::IN);
            f(&self.name, RRType::AAAA, Class::IN);
        }
        LookupHostRunner::new()
    }
}


//------------ LookupHostRunner ---------------------------------------------

pub struct LookupHostRunner {
    /// The response to our A query, if it has arrived yet.
    a: Option<Result<MessageBuf>>,

    /// The response to our AAAA query, if it has arrived yet.
    aaaa: Option<Result<MessageBuf>>
}

impl LookupHostRunner {
    pub fn new() -> Self {
        LookupHostRunner { a: None, aaaa: None }
    }

    fn process(self) -> Progress<Self, HostSuccess> {
        match (self.a, self.aaaa) {
            (Some(a), Some(aaaa)) => HostSuccess::new(a, aaaa).into(),
            (a, aaaa) => {
                Progress::Continue(LookupHostRunner { a: a, aaaa: aaaa })
            }
        }
    }
}

impl TaskRunner for LookupHostRunner {
    type Success = HostSuccess;

    fn progress<F>(mut self, response: MessageBuf, _f: F)
                   -> Progress<Self, HostSuccess>
                where F: FnMut(&DName, RRType, Class) {
        let qtype = response.qtype();
        match qtype {
            Some(RRType::A) => self.a = Some(Ok(response)),
            Some(RRType::AAAA) => self.aaaa = Some(Ok(response)),
            _ => { }
        };
        self.process()
    }

    fn error<'a, F>(mut self, question: &Question<'a>, error: Error, _f: F)
                    -> Progress<Self, HostSuccess>
             where F: FnMut(&DName, RRType, Class) {
        match question.qtype() {
            RRType::A => self.a = Some(Err(error)),
            RRType::AAAA => self.aaaa = Some(Err(error)),
            _ => { }
        };
        self.process()
    }
}


//------------ HostSuccess --------------------------------------------

pub struct HostSuccess {
    canonical: DNameBuf,
    addrs: Vec<IpAddr>
}

impl HostSuccess {
    /// Create a new value from A and AAAA results.
    fn new(mut a: Result<MessageBuf>, mut aaaa: Result<MessageBuf>)
           -> Result<Self> {
        // Turn any error response into an error.
        a = match a {
            Ok(ref msg) if !msg.no_error() => Err(Error::NoName),
            _ => a
        };
        aaaa = match aaaa {
            Ok(ref msg) if !msg.no_error() => Err(Error::NoName),
            _ => aaaa
        };

        if let Ok(a) = a {
            let name = a.canonical_name().unwrap();
            let mut addrs = Vec::new();
            process_records(&a, &name, &mut addrs,
                            |r: &A| IpAddr::V4(r.addr())).ok();
            if let Ok(aaaa) = aaaa {
                process_records(&aaaa, &name, &mut addrs,
                                |r: &AAAA| IpAddr::V6(r.addr())).ok();
            }
            Ok(HostSuccess { canonical: name.into_owned(),
                                   addrs: addrs })
        }
        else if let Ok(aaaa) = aaaa {
            let name = aaaa.canonical_name().unwrap();
            let mut addrs = Vec::new();
            process_records(&aaaa, &name, &mut addrs,
                            |r: &AAAA| IpAddr::V6(r.addr())).ok();
            Ok(HostSuccess { canonical: name.into_owned(),
                                   addrs: addrs })
        }
        else {
            // Two errors? Absolutely not.
            return Err(a.unwrap_err())
        }
    }

    /// Returns the canonical name for the host.
    ///
    /// This may or may not be the name you asked for.
    pub fn canonical_name(&self) -> &DNameSlice {
        &self.canonical
    }

    /// Returns an iterator over the IP addresses.
    pub fn iter(&self) -> slice::Iter<IpAddr> {
        self.addrs.iter()
    }
}

/// Push all records of type R with given name into addrs using f.
///
/// Returns a `ParseResult` only so we can use try.
fn process_records<'a, R, F>(response: &'a MessageBuf, name: &DNameSlice, 
                             addrs: &mut Vec<IpAddr>, f: F) -> ParseResult<()>
           where R: RecordData<'a>,
                 F: Fn(&R) -> IpAddr {
    for record in try!(response.answer()).iter::<R>() {
        let record = try!(record);
        if record.name() == name {
            addrs.push(f(record.rdata()))
        }
    }
    Ok(())
}


//------------ SearchHost ---------------------------------------------------

/// Searches for all IP addresses for the given host.
///
/// This task allows looking up relative names. These are considered based on
/// the resolver configuration. If the name has less dots than set in the
/// `ndots` attribute of the configuration (the default is one), then each
/// domain name in the configuration’s `search` list is appened to the name
/// and the result looked up. Otherwise, the root label is added to the name
/// and that is looked up.
pub struct SearchHost {
    names: Vec<DNameBuf>,
}

impl SearchHost {
    pub fn new<N: AsRef<DNameSlice>>(name: &N, conf: &ResolvConf) -> Self {
        let name = name.as_ref();
        if name.iter().count() > conf.ndots {
            SearchHost { names: vec!(name.join(DNameSlice::root())) }
        }
        else {
            assert!(!conf.search.is_empty());

            let mut vec = Vec::new();
            for suffix in conf.search.iter().rev() {
                println!("Looking for: {}", name.join(suffix));
                vec.push(name.join(suffix))
            }
            SearchHost { names: vec }
        }
    }
}

impl Task for SearchHost {
    type Runner = SearchHostRunner;

    fn start<F>(mut self, f: F) -> Self::Runner
             where F: FnMut(&DName, RRType, Class) {
        let name = self.names.pop().unwrap();
        let inner = LookupHost::new(name.as_dname());
        let inner = inner.start(f);
        SearchHostRunner { names: self.names, inner: inner }
    }
}


//------------ SearchHostRunner ---------------------------------------------

pub struct SearchHostRunner {
    names: Vec<DNameBuf>,
    inner: LookupHostRunner,
}

impl SearchHostRunner {
    fn new(names: Vec<DNameBuf>, inner: LookupHostRunner) -> Self {
        SearchHostRunner { names: names, inner: inner }
    }
}

impl TaskRunner for SearchHostRunner {
    type Success = HostSuccess;

    fn progress<F>(self, response: MessageBuf, f: F)
                   -> Progress<Self, HostSuccess>
                where F: FnMut(&DName, RRType, Class) {
        let (names, inner) = (self.names, self.inner);
        inner.progress(response, f)
             .map_continue(|x| SearchHostRunner::new(names, x))
    }

    fn error<'a, F>(self, question: &Question<'a>, error: Error, f: F)
                    -> Progress<Self, HostSuccess>
             where F: FnMut(&DName, RRType, Class) {
        let (names, inner) = (self.names, self.inner);
        inner.error(question, error, f)
             .map_continue(|x| SearchHostRunner::new(names, x))
    }
}

