//! Tasks for looking up address names.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use bits::{AsDName, Class, DName, DNameBuf, MessageBuf, Question, RRType};
use bits::name::Label;
use rdata::Ptr;
use resolv::Error;
use resolv::tasks::traits::{Progress, Task, TaskRunner};

//------------ LookupAddr ---------------------------------------------------

pub struct LookupAddr {
    addr: IpAddr,
}

impl LookupAddr {
    pub fn new(addr: IpAddr) -> Self {
        LookupAddr { addr: addr }
    }
}

impl Task for LookupAddr {
    type Runner = LookupAddrRunner;

    fn start<F>(self, mut f: F) -> Self::Runner
             where F: FnMut(&DName, RRType, Class) {
        let name = dname_from_addr(self.addr);
        f(&name.as_dname(), RRType::PTR, Class::IN);
        LookupAddrRunner { name: name }
    }
}


//------------ LookupAddrRunner ---------------------------------------------

pub struct LookupAddrRunner {
    name: DNameBuf
}

impl TaskRunner for LookupAddrRunner {
    type Success = DNameBuf;

    fn progress<F>(self, response: MessageBuf, _f: F)
                   -> Progress<Self, Self::Success>
                where F: FnMut(&DName, RRType, Class) {
        if response.is_error() {
            return Progress::Error(Error::NoName)
        }
        let answer = match response.answer() {
            Err(..) => return Progress::Error(Error::NoName),
            Ok(answer) => answer,
        };
        for record in answer.iter::<Ptr>() {
            if let Ok(record) = record {
                if record.class() == Class::IN && self.name == *record.name() {
                    if let Ok(name) = record.rdata().ptrdname().to_owned() {
                        return Progress::Success(name)
                    }
                }
            }
        }
        Progress::Error(Error::NoName)
    }

    fn error<'a, F>(self, _question: &Question<'a>, error: Error, _f: F)
                    -> Progress<Self, Self::Success>
             where F: FnMut(&DName, RRType, Class) {
        Progress::Error(error)
    }
}


//------------ Helper Functions ---------------------------------------------

fn dname_from_addr(addr: IpAddr) -> DNameBuf {
    match addr {
        IpAddr::V4(addr) => dname_from_v4(addr),
        IpAddr::V6(addr) => dname_from_v6(addr)
    }
}

fn dname_from_v4(addr: Ipv4Addr) -> DNameBuf {
    let octets = addr.octets();
    DNameBuf::from_str(&format!("{}.{}.{}.{}.in-addr.arpa.", octets[3],
                                octets[2], octets[1], octets[0])).unwrap()
}

fn dname_from_v6(addr: Ipv6Addr) -> DNameBuf {
    let mut res = DNameBuf::new();
    for item in addr.segments().iter().rev() {
        let text = format!("{:04x}", item);
        let text = text.as_bytes();
        res.push(&Label::normal(&text[3..4]));
        res.push(&Label::normal(&text[2..3]));
        res.push(&Label::normal(&text[1..2]));
        res.push(&Label::normal(&text[0..1]));
    }
    res.push(&Label::normal(b"ip6"));
    res.push(&Label::normal(b"arpa"));
    res.push(&Label::root());
    res
}

