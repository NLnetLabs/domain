//! Record data from [RFC 3596].
//!
//! This RFC defines the Aaaa record type.
//!
//! [RFC 3596]: https://tools.ietf.org/html/rfc3596

use std::fmt;
use std::net::Ipv6Addr;
use std::io;
use std::str::FromStr;
use ::bits::bytes::BytesBuf;
use ::bits::compose::ComposeBytes;
use ::bits::error::{ComposeResult, ParseResult};
use ::bits::name::{AsDName, DNameSlice};
use ::bits::parse::ParseBytes;
use ::bits::rdata::RecordData;
use ::bits::record::{push_record, RecordTarget};
use ::iana::{Class, RRType};
use ::master;


//------------ Aaaa ---------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Aaaa {
    addr: Ipv6Addr
}

impl Aaaa {
    pub fn new(addr: Ipv6Addr) -> Aaaa {
        Aaaa { addr: addr }
    }

    pub fn addr(&self) -> Ipv6Addr { self.addr }
    pub fn set_addr(&mut self, addr: Ipv6Addr) { self.addr = addr }

    pub fn push<C, T, N>(target: &mut T, name: &N, ttl: u32,
                         addr: &Ipv6Addr) -> ComposeResult<()>
                where C: ComposeBytes, T: RecordTarget<C>, N: AsDName {
        push_record(target, name, RRType::Aaaa, Class::In, ttl, |target| {
            for i in addr.segments().iter() {
                try!(target.push_u16(*i))
            }
            Ok(())
        })
    }

    pub fn scan_into<R, B>(stream: &mut master::Stream<R>,
                           _origin: &DNameSlice, target: &mut B)
                              -> master::Result<()>
                     where R: io::Read, B: BytesBuf {
        stream.scan_str_phrase(|slice| {
            let addr = try!(Ipv6Addr::from_str(slice));
            for i in addr.segments().iter() {
                target.push_u16(*i)
            }
            Ok(())
        })
    }

    fn parse_always<'a, P>(parser: &mut P) -> ParseResult<Self>
                    where P: ParseBytes<'a> {
        Ok(Aaaa::new(Ipv6Addr::new(try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()))))
    }
}

impl<'a> RecordData<'a> for Aaaa {
    fn rtype(&self) -> RRType { RRType::Aaaa }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.addr.segments().iter() {
            try!(target.push_u16(*i));
        }
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Aaaa { Some(Aaaa::parse_always(parser)) }
        else { None }
    }
}

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}

