//! Record data from [RFC 1035].
//!
//! This RFC defines the initial set of record types.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use std::borrow::Cow;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use ::bits::bytes::BytesBuf;
use ::bits::compose::ComposeBytes;
use ::bits::charstr::CharStr;
use ::bits::error::{ComposeResult, ParseResult};
use ::bits::name::{AsDName, DName, DNameSlice};
use ::bits::octets::Octets;
use ::bits::parse::ParseBytes;
use ::bits::record::{push_record, RecordTarget};
use ::bits::rdata::RecordData;
use ::iana::{Class, RRType};
use ::master::{Scanner, ScanResult, SyntaxError};
use ::utils::netdb::{ProtoEnt, ServEnt};


//------------ dname_type! --------------------------------------------------

/// A macro for implementing a record data type with a single domain name.
///
/// Implements some basic methods plus the RecordData, FlatRecordData, and
/// Display traits.
macro_rules! dname_type {
    ($target:ident, $rtype:ident, $field:ident) => {
        impl<'a> $target<'a> {
            pub fn new($field: DName<'a>) -> Self {
                $target { $field: $field }
            }

            pub fn $field(&self) -> DName<'a> {
                self.$field.clone()
            }

            fn parse_always<P>(parser: &mut P) -> ParseResult<Self>
                            where P: ParseBytes<'a> {
                Ok($target::new(try!(parser.parse_dname())))
            }

            pub fn push<C, T, N, V>(target: &mut T, name: &N, class: Class,
                                    ttl: u32, value: &V) -> ComposeResult<()>
                        where C: ComposeBytes, T: RecordTarget<C>, N: AsDName,
                              V: AsDName {
                push_record(target, name, RRType::$rtype, class, ttl,
                            |target| target.push_dname_compressed(value))
            }

            pub fn scan_into<S: Scanner>(scanner: &mut S,
                                         origin: Option<&DNameSlice>,
                                         target: &mut Vec<u8>)
                                         -> ScanResult<()> {
                scanner.scan_dname_into(origin, target)
            }
        }

        impl<'a> RecordData<'a> for $target<'a> {
            fn rtype(&self) -> RRType { RRType::$rtype }

            fn compose<C: ComposeBytes>(&self, target: &mut C)
                                        -> ComposeResult<()> {
                target.push_dname_compressed(&self.$field)
            }
        
            fn parse<P>(rtype: RRType, parser: &mut P)
                        -> Option<ParseResult<Self>>
                     where P: ParseBytes<'a> {
                if rtype == RRType::$rtype {
                    Some($target::parse_always(parser))
                }
                else { None }
            }
        }


        impl<'a> fmt::Display for $target<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.$field.fmt(f)
            }
        }
    }
}

//------------ A ------------------------------------------------------------

/// A record data.
///
/// A records convey the IPv4 address of a host. The wire format is the 32
/// bit IPv4 address in network byte order. The master file format is the
/// usual dotted notation.
///
/// The A record type is defined in RFC 1035, section 3.4.1.
#[derive(Clone, Debug, PartialEq)]
pub struct A {
    addr: Ipv4Addr,
}

impl A {
    /// Creates a new A record data from an IPv4 address.
    pub fn new(addr: Ipv4Addr) -> A {
        A { addr: addr }
    }

    /// Creates a new A record from the IPv4 address components.
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8) -> A {
        A::new(Ipv4Addr::new(a, b, c, d))
    }

    pub fn addr(&self) -> Ipv4Addr { self.addr }
    pub fn set_addr(&mut self, addr: Ipv4Addr) { self.addr = addr }

    pub fn push<C, T, N>(target: &mut T, name: &N, ttl: u32,
                         addr: &Ipv4Addr) -> ComposeResult<()>
                where C: ComposeBytes, T: RecordTarget<C>, N: AsDName {
        push_record(target, name, RRType::A, Class::In, ttl, |target| {
            for i in &addr.octets() {
                try!(target.push_u8(*i))
            }
            Ok(())
        })
    }

    pub fn push_from_octets<C, T, N>(target: &mut T, name: &N, ttl: u32,
                                     a: u8, b: u8, c: u8, d: u8)
                                     -> ComposeResult<()>
                where C: ComposeBytes, T: RecordTarget<C>, N: AsDName {
        A::push(target, name, ttl, &Ipv4Addr::new(a, b, c, d))
    }

    pub fn rtype() -> RRType { RRType::A }

    fn parse_always<'a, P>(parser: &mut P) -> ParseResult<Self>
                    where P: ParseBytes<'a> {
        Ok(A::new(Ipv4Addr::new(try!(parser.parse_u8()),
                                try!(parser.parse_u8()),
                                try!(parser.parse_u8()),
                                try!(parser.parse_u8()))))
    }

    pub fn scan_into<S: Scanner>(scanner: &mut S,
                                 _origin: Option<&DNameSlice>,
                                 target: &mut Vec<u8>)
                                 -> ScanResult<()> {
        scanner.scan_str_phrase(|slice| {
            let addr = try!(Ipv4Addr::from_str(slice));
            target.push_bytes(&addr.octets()[..]);
            Ok(())
        })
    }
}

impl<'a> RecordData<'a> for A {
    fn rtype(&self) -> RRType { A::rtype() }
    
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in &self.addr.octets() {
            try!(target.push_u8(*i))
        }
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::A { Some(A::parse_always(parser)) }
        else { None }
    }
}


impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}


//------------ Cname --------------------------------------------------------

/// CNAME record data.
///
/// The CNAME record specifies the canonical or primary name for domain
/// name alias.
///
/// The CNAME type is defined in RFC 1035, section 3.3.1.
#[derive(Clone, Debug, PartialEq)]
pub struct Cname<'a> {
    cname: DName<'a>
}

dname_type!(Cname, Cname, cname);


//------------ Hinfo --------------------------------------------------------

/// Hinfo record data.
///
/// Hinfo records are used to acquire general information about a host,
/// specifically the CPU type and operating system type.
///
/// The Hinfo type is defined in RFC 1035, section 3.3.2.
#[derive(Clone, Debug, PartialEq)]
pub struct Hinfo<'a> {
    cpu: CharStr<'a>,
    os: CharStr<'a>
}

impl<'a> Hinfo<'a> {
    /// Creates a new Hinfo record data from the components.
    pub fn new(cpu: CharStr<'a>, os: CharStr<'a>) -> Self {
        Hinfo { cpu: cpu, os: os }
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &CharStr<'a> {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &CharStr<'a> {
        &self.os
    }

    fn parse_always<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        Ok(Hinfo::new(try!(parser.parse_charstr()),
                      try!(parser.parse_charstr())))
    }

    pub fn scan_into<S: Scanner>(scanner: &mut S,
                                 _origin: Option<&DNameSlice>,
                                 target: &mut Vec<u8>)
                                 -> ScanResult<()> {
        try!(scanner.scan_charstr_into(target));
        scanner.scan_charstr_into(target)
    }
}

impl<'a> RecordData<'a> for Hinfo<'a> {
    fn rtype(&self) -> RRType { RRType::Hinfo }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        try!(target.push_charstr(&self.cpu));
        try!(target.push_charstr(&self.os));
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Hinfo { Some(Hinfo::parse_always(parser)) }
        else { None }
    }
}

impl<'a> fmt::Display for Hinfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}


//------------ Mb -----------------------------------------------------------

/// MB record data.
///
/// The experimental MB record specifies a host that serves a mailbox.
///
/// The MB record type is defined in RFC 1035, section 3.3.3.
#[derive(Clone, Debug, PartialEq)]
pub struct Mb<'a> {
    madname: DName<'a>
}

dname_type!(Mb, Mb, madname);


//------------ Md -----------------------------------------------------------

/// MD record data.
///
/// The MD record specifices a host which has a mail agent for
/// the domain which should be able to deliver mail for the domain.
/// 
/// The MD record is obsolete. It is recommended to either reject the record
/// or convert them into an Mx record at preference 0.
///
/// The MD record type is defined in RFC 1035, section 3.3.4.
#[derive(Clone, Debug, PartialEq)]
pub struct Md<'a> {
    madname: DName<'a>
}

dname_type!(Md, Md, madname);


//------------ Mf -----------------------------------------------------------

/// MF record data.
///
/// The MF record specifices a host which has a mail agent for
/// the domain which will be accept mail for forwarding to the domain.
/// 
/// The MF record is obsolete. It is recommended to either reject the record
/// or convert them into an Mx record at preference 10.
///
/// The MF record type is defined in RFC 1035, section 3.3.5.
#[derive(Clone, Debug, PartialEq)]
pub struct Mf<'a> {
    madname: DName<'a>
}

dname_type!(Mf, Mf, madname);


//------------ Mg -----------------------------------------------------------

/// MG record data.
///
/// The MG record specifices a mailbox which is a member of the mail group
/// specified by the domain name.
/// 
/// The MG record is experimental.
///
/// The MG record type is defined in RFC 1035, section 3.3.6.
#[derive(Clone, Debug, PartialEq)]
pub struct Mg<'a> {
    madname: DName<'a>
}

dname_type!(Mg, Mg, madname);


//------------ Minfo --------------------------------------------------------

/// Minfo record data.
///
/// The Minfo record specifies a mailbox which is responsible for the mailing
/// list or mailbox and a mailbox that receives error messages related to the
/// list or box.
///
/// The Minfo record is experimental.
///
/// The Minfo record type is defined in RFC 1035, section 3.3.7.
#[derive(Clone, Debug, PartialEq)]
pub struct Minfo<'a> {
    rmailbx: DName<'a>,
    emailbx: DName<'a>
}

impl<'a> Minfo<'a> {
    /// Creates a new Minfo record data from the components.
    pub fn new(rmailbx: DName<'a>, emailbx: DName<'a>) -> Self {
        Minfo { rmailbx: rmailbx, emailbx: emailbx }
    }

    /// The responsible mail box.
    ///
    /// The domain name specifies the mailbox which is responsible for the
    /// mailing list or mailbox. If this domain name is the root, the owner
    /// of the Minfo record is responsible for itself.
    pub fn rmailbx(&self) -> &DName<'a> {
        &self.rmailbx
    }

    /// The error mail box.
    ///
    /// The domain name specifies a mailbox which is to receive error
    /// messages related to the mailing list or mailbox specified by the
    /// owner of the record. If this is the root domain name, errors should
    /// be returned to the sender of the message.
    pub fn emailbx(&self) -> &DName<'a> {
        &self.emailbx
    }

    fn parse_always<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        Ok(Minfo::new(try!(parser.parse_dname()),
                      try!(parser.parse_dname())))
    }

    pub fn scan_into<S: Scanner>(scanner: &mut S,
                                 origin: Option<&DNameSlice>,
                                 target: &mut Vec<u8>)
                                 -> ScanResult<()> {
        try!(scanner.scan_dname_into(origin, target));
        scanner.scan_dname_into(origin, target)
    }
}

impl<'a> RecordData<'a> for Minfo<'a> {
    fn rtype(&self) -> RRType { RRType::Minfo }

    fn compose<C: ComposeBytes>(&self, target: &mut C)
                                -> ComposeResult<()> {
        try!(target.push_dname(&self.rmailbx));
        try!(target.push_dname(&self.emailbx));
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Minfo { Some(Minfo::parse_always(parser)) }
        else { None }
    }
}

impl<'a> fmt::Display for Minfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.rmailbx, self.emailbx)
    }
}


//------------ Mr -----------------------------------------------------------

/// MR record data.
///
/// The MR record specifices a mailbox which is the proper rename of the
/// specified mailbox.
/// 
/// The MR record is experimental.
///
/// The MR record type is defined in RFC 1035, section 3.3.8.
#[derive(Clone, Debug, PartialEq)]
pub struct Mr<'a> {
    newname: DName<'a>
}

dname_type!(Mr, Mr, newname);


//------------ Mx -----------------------------------------------------------

/// Mx record data.
///
/// The Mx record specifies a host willing to serve as a mail exchange for
/// the owner name.
///
/// The Mx record type is defined in RFC 1035, section 3.3.9.
#[derive(Clone, Debug, PartialEq)]
pub struct Mx<'a> {
    preference: u16,
    exchange: DName<'a>,
}

impl<'a> Mx<'a> {
    /// Creates a new Mx record data from the components.
    pub fn new(preference: u16, exchange: DName<'a>) -> Self {
        Mx { preference: preference, exchange: exchange }
    }

    /// The preference for this record.
    ///
    /// Defines an order if there are several Mx records for the same owner.
    /// Lower values are preferred.
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// The name of the host that is the exchange.
    pub fn exchange(&self) -> &DName<'a> {
        &self.exchange
    }

    fn parse_always<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        Ok(Mx::new(try!(parser.parse_u16()),
                   try!(parser.parse_dname())))
    }

    pub fn scan_into<S: Scanner>(scanner: &mut S,
                                 origin: Option<&DNameSlice>,
                                 target: &mut Vec<u8>)
                                 -> ScanResult<()> {
        target.push_u16(try!(scanner.scan_u16()));
        scanner.scan_dname_into(origin, target)
    }
}

impl<'a> RecordData<'a> for Mx<'a> {
    fn rtype(&self) -> RRType { RRType::Mx }

    fn compose<C: ComposeBytes>(&self, target: &mut C)
                                -> ComposeResult<()> {
        try!(target.push_u16(self.preference));
        try!(target.push_dname(&self.exchange));
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Mx { Some(Mx::parse_always(parser)) }
        else { None }
    }
}

impl<'a> fmt::Display for Mx<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}


//------------ Ns -----------------------------------------------------------

/// NS record data.
///
/// NS records specify hosts that are authoritative for a class and domain.
///
/// The NS record type is defined in RFC 1035, section 3.3.11.
#[derive(Clone, Debug, PartialEq)]
pub struct Ns<'a> {
    nsdname: DName<'a>
}

dname_type!(Ns, Ns, nsdname);


//------------ Null ---------------------------------------------------------

/// Null record data.
///
/// Null records can contain whatever data. They are experimental, not
/// allowed in master files.
///
/// The Null record type is defined in RFC 1035, section 3.3.10.
#[derive(Clone, Debug, PartialEq)]
pub struct Null<'a> {
    data: Octets<'a>
}

impl<'a> Null<'a> {
    /// Creates new, empty owned Null record data.
    pub fn new(data: Octets<'a>) -> Self {
        Null { data: data }
    }

    /// The raw content of the record.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    fn parse_always<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let len = parser.left();
        Ok(Null::new(try!(parser.parse_octets(len))))
    }
}

impl<'a> RecordData<'a> for Null<'a> {
    fn rtype(&self) -> RRType { RRType::Null }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_octets(&self.data)
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Null { Some(Null::parse_always(parser)) }
        else { None }
    }
}

impl<'a> fmt::Display for Null<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "\\# {} ", self.data.len()));
        let mut iter = self.data.iter();
        loop {
            for _ in 0..8 {
                match iter.next() {
                    Some(ch) => try!(write!(f, "{:02x}", ch)),
                    None => return Ok(()),
                }
            }
        }
    }
}


//------------ Ptr ----------------------------------------------------------

/// PTR record data.
///
/// PRT records are used in special domains to point to some other location
/// in the domain space.
///
/// The PTR record type is defined in RFC 1035, section 3.3.12.
#[derive(Clone, Debug, PartialEq)]
pub struct Ptr<'a> {
    ptrdname: DName<'a>
}

dname_type!(Ptr, Ptr, ptrdname);


//------------ Soa ----------------------------------------------------------

/// Soa record data.
///
/// Soa records mark the top of a zone and contain information pertinent for
/// name server maintenance operations.
///
/// The Soa record type is defined in RFC 1035, section 3.3.13.
#[derive(Clone, Debug, PartialEq)]
pub struct Soa<'a> {
    mname: DName<'a>,
    rname: DName<'a>,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32
}

impl<'a> Soa<'a> {
    /// Creates new Soa record data from content.
    pub fn new(mname: DName<'a>, rname: DName<'a>, serial: u32,
               refresh: u32, retry: u32, expire: u32, minimum: u32) -> Self {
        Soa { mname: mname, rname: rname, serial: serial,
              refresh: refresh, retry: retry, expire: expire,
              minimum: minimum }
    }

    /// The primary name server for the zone.
    pub fn mname(&self) -> &DName<'a> {
        &self.mname
    }

    /// The mailbox for the person responsible for this zone.
    pub fn rname(&self) -> &DName<'a> {
        &self.rname
    }

    /// The serial number of the original copy of the zone.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// The time interval in seconds before the zone should be refreshed.
    pub fn refresh(&self) -> u32 {
        self.refresh
    }

    /// The time in seconds before a failed refresh is retried.
    pub fn retry(&self) -> u32 {
        self.retry
    }

    /// The upper limit of time in seconds the zone is authoritative.
    pub fn expire(&self) -> u32 {
        self.expire
    }

    /// The minimum TTL to be exported with any RR from this zone.
    pub fn minimum(&self) -> u32 {
        self.minimum
    }

    fn parse_always<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        Ok(Soa::new(try!(parser.parse_dname()), try!(parser.parse_dname()),
                    try!(parser.parse_u32()), try!(parser.parse_u32()),
                    try!(parser.parse_u32()), try!(parser.parse_u32()),
                    try!(parser.parse_u32())))
    }

    pub fn scan_into<S: Scanner>(scanner: &mut S,
                                 origin: Option<&DNameSlice>,
                                 target: &mut Vec<u8>)
                                 -> ScanResult<()> {
        try!(scanner.scan_dname_into(origin, target));
        try!(scanner.scan_dname_into(origin, target));
        target.push_u32(try!(scanner.scan_u32()));
        target.push_u32(try!(scanner.scan_u32()));
        target.push_u32(try!(scanner.scan_u32()));
        target.push_u32(try!(scanner.scan_u32()));
        target.push_u32(try!(scanner.scan_u32()));
        Ok(())
    }
}

impl<'a> RecordData<'a> for Soa<'a> {
    fn rtype(&self) -> RRType { RRType::Soa }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        try!(target.push_dname(&self.mname));
        try!(target.push_dname(&self.rname));
        try!(target.push_u32(self.serial));
        try!(target.push_u32(self.refresh));
        try!(target.push_u32(self.retry));
        try!(target.push_u32(self.expire));
        try!(target.push_u32(self.minimum));
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Soa { Some(Soa::parse_always(parser)) }
        else { None }
    }
}

impl<'a> fmt::Display for Soa<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {}", self.mname, self.rname,
               self.serial, self.refresh, self.retry, self.expire,
               self.minimum)
    }
}


//------------ Txt ----------------------------------------------------------

/// Txt record data.
///
/// Txt records hold descriptive text.
///
/// The Txt record type is defined in RFC 1035, section 3.3.14.
#[derive(Clone, Debug, PartialEq)]
pub struct Txt<'a> {
    text: Cow<'a, [u8]>
}

impl<'a> Txt<'a> {
    /// Creates a new Txt record from content.
    pub fn new(text: Cow<'a, [u8]>) -> Self {
        Txt { text: text }
    }

    /// Returns an iterator over the text items.
    ///
    /// The Txt format contains one or more length-delimited byte strings.
    /// This method returns an iterator over each of them.
    pub fn iter(&self) -> TxtIter {
        TxtIter::new(&self.text)
    }

    /// Returns the text content.
    ///
    /// If the raw content is only a single character-string, returns a
    /// borrow else creates an owned vec by concatenating all the parts.
    pub fn text(&self) -> Cow<[u8]> {
        if self.text.len() == 0 {
            Cow::Borrowed(b"")
        }
        else if (self.text[0] as usize) == self.text.len() - 1 {
            Cow::Borrowed(&self.text[1..])
        }
        else {
            let mut res = Vec::new();
            for item in self.iter() {
                res.extend_from_slice(&item)
            }
            Cow::Owned(res)
        }
    }

    fn parse_always<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let len = parser.left();
        Ok(Txt::new(Cow::Borrowed(try!(parser.parse_bytes(len)))))
    }

    pub fn scan_into<S: Scanner>(scanner: &mut S,
                                 _origin: Option<&DNameSlice>,
                                 target: &mut Vec<u8>)
                                 -> ScanResult<()> {
        let mut len = 0;
        let mut pos = target.len();
        target.push_u8(0);
        try!(scanner.scan_phrase_bytes(|ch, _| {
            target.push_u8(ch);
            if len == 254 {
                target[pos] = 255;
                len = 0;
                pos = target.len();
                target.push_u8(0);
            }
            else {
                len += 1
            }
            Ok(())
        }));
        target[pos] = len;
        Ok(())
    }
}

impl<'a> RecordData<'a> for Txt<'a> {
    fn rtype(&self) -> RRType { RRType::Txt }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_bytes(&self.text)
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Txt { Some(Txt::parse_always(parser)) }
        else { None }
    }
}

impl<'a> fmt::Display for Txt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for text in self.iter() {
            try!(text.fmt(f))
        }
        Ok(())
    }
}


//--- TxtIter

/// An iterator over the character strings of a Txt record.
#[derive(Clone, Debug, PartialEq)]
pub struct TxtIter<'a> {
    text: &'a [u8],
}

impl<'a> TxtIter<'a> {
    fn new(text: &'a [u8])-> Self {
        TxtIter { text: text }
    }
}

impl<'a> Iterator for TxtIter<'a> {
    type Item = CharStr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.text.split_first().map(|(len, tail)| {
            let len = *len as usize;
            if tail.len() <= len {
                self.text = b"";
                CharStr::borrowed(tail).unwrap()
            }
            else {
                let (head, tail) = tail.split_at(len);
                self.text = tail;
                CharStr::borrowed(head).unwrap()
            }
        })
    }
}


//------------ Wks ----------------------------------------------------------

/// Wks record data.
///
/// Wks records describe the well-known services supported by a particular
/// protocol on a particular internet address.
///
/// The Wks record type is defined in RFC 1035, section 3.4.2.
#[derive(Clone, Debug, PartialEq)]
pub struct Wks<'a> {
    address: Ipv4Addr,
    protocol: u8,
    bitmap: WksBitmap<'a>
}

impl<'a> Wks<'a> {
    /// Creates a new record data from components.
    pub fn new(address: Ipv4Addr, protocol: u8, bitmap: WksBitmap<'a>)
               -> Self {
        Wks { address: address, protocol: protocol, bitmap: bitmap }
    }

    /// The IPv4 address of the host this record refers to.
    pub fn address(&self) -> &Ipv4Addr {
        &self.address
    }

    /// The protocol number of the protocol this record refers to.
    ///
    /// This will typically be `6` for TCP or `17` for UDP.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// A bitmap indicating the ports where service is being provided.
    pub fn bitmap(&self) -> &WksBitmap {
        &self.bitmap
    }


    fn parse_always<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let addr = Ipv4Addr::new(try!(parser.parse_u8()),
                                 try!(parser.parse_u8()),
                                 try!(parser.parse_u8()),
                                 try!(parser.parse_u8()));
        let proto = try!(parser.parse_u8());
        let len = parser.left();
        let bitmap = try!(WksBitmap::parse(parser, len));
        Ok(Wks::new(addr, proto, bitmap))
    }

    /// Returns whether a certain service is being provided.
    pub fn serves(&self, port: u16) -> bool {
        self.bitmap.serves(port)
    }

    /// Returns an iterator over the served ports.
    pub fn iter(&self) -> WksIter {
        self.bitmap.iter()
    }

    /// Scan the master file representation of a WKS record into a target.
    ///
    pub fn scan_into<S: Scanner>(scanner: &mut S,
                                 origin: Option<&DNameSlice>,
                                 target: &mut Vec<u8>)
                                 -> ScanResult<()> {
        try!(A::scan_into(scanner, origin, target));
        try!(scanner.scan_str_phrase(|s| {
            if let Some(ent) = ProtoEnt::by_name(s) {
                target.push_u8(ent.proto);
                Ok(())
            }
            else if let Ok(number) = u8::from_str_radix(s, 10) {
                target.push_u8(number);
                Ok(())
            }
            else {
                Err(SyntaxError::UnknownProto(s.into()))
            }
        }));

        let mut bitmap = WksBitmap::new();
        while let Ok(()) = scanner.scan_str_phrase(|s| {
            if let Some(ent) = ServEnt::by_name(s) {
                bitmap.set_serves(ent.port, true);
                Ok(())
            }
            else if let Ok(number) = u16::from_str_radix(s, 10) {
                bitmap.set_serves(number, true);
                Ok(())
            }
            else {
                Err(SyntaxError::UnknownServ(s.into()))
            }
        }) { }
        target.push_bytes(bitmap.as_bytes());
        Ok(())
    }
}

impl<'a> RecordData<'a> for Wks<'a> {
    fn rtype(&self) -> RRType { RRType::Wks }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in &self.address.octets() {
            try!(target.push_u8(*i))
        }
        try!(target.push_u8(self.protocol));
        self.bitmap.compose(target)
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Wks { Some(Wks::parse_always(parser)) }
        else { None }
    }
}

impl<'a> fmt::Display for Wks<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "{} {}", self.address, self.protocol));
        for port in self.iter() {
            try!(write!(f, " {}", port));
        }
        Ok(())
    }
}


//--- WksBitmap

/// The type of the bitmap of a WKS record.
#[derive(Clone, Debug, Default)]
pub struct WksBitmap<'a>(Cow<'a, [u8]>);

impl<'a> WksBitmap<'a> {
    pub fn new() -> Self {
        WksBitmap(Cow::Owned(Vec::new()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns whether a certain service is being provided.
    pub fn serves(&self, port: u16) -> bool {
        let (octet, bit) = WksBitmap::port_location(port);
        if self.0.len() <= octet { false }
        else { (self.0[octet] >> bit) > 0 }
    }

    /// Enables or disables the given service.
    pub fn set_serves(&mut self, port: u16, enable: bool) {
        let (octet, bit) = WksBitmap::port_location(port);
        let bitmap = self.0.to_mut();
        if bitmap.len() <= octet {
            bitmap.resize(octet + 1, 0);
        }
        if enable {
            bitmap[octet] |= 1 << bit
        }
        else {
            bitmap[octet] &= 0xFF ^ (1 << bit)
        }
    }

    /// Returns an iterator over the served ports.
    pub fn iter(&self) -> WksIter {
        WksIter::new(&self.0)
    }

    /// Translates a port number to where it’ll be in the bitmap.
    ///
    /// Returns a pair of the index in the bytes slice and the bit number in
    /// that slice.
    fn port_location(port: u16) -> (usize, usize) {
        ((port / 8) as usize, (port % 8) as usize)
    }

    pub fn parse<P: ParseBytes<'a>>(parser: &mut P, len: usize)
                                    -> ParseResult<Self> {
        Ok(WksBitmap(Cow::Borrowed(try!(parser.parse_bytes(len)))))
    }

    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        target.push_bytes(&self.0)
    }
}

impl<'a, 'b> PartialEq<WksBitmap<'b>> for WksBitmap<'a> {
    fn eq(&self, other: &WksBitmap<'b>) -> bool {
        use std::ops::Deref;

        // Drop any trailing zeros from the slices, the compare those.
        let mut s = self.0.deref();
        while let Some((&0, head)) = s.split_last() { s = head }
        let mut o = other.0.deref();
        while let Some((&0, head)) = o.split_last() { o = head }
        s == o
    }
}
 

//--- WksIter

/// An iterator over the services active in a Wks record.
///
/// This iterates over the port numbers in growing order.
#[derive(Clone, Debug, PartialEq)]
pub struct WksIter<'a> {
    bitmap: &'a [u8],
    octet: usize,
    bit: usize
}

impl<'a> WksIter<'a> {
    fn new(bitmap: &'a [u8]) -> Self {
        WksIter { bitmap: bitmap, octet: 0, bit: 0 }
    }

    fn serves(&self) -> bool {
        (self.bitmap[self.octet] >> self.bit) > 0
    }
}

impl<'a> Iterator for WksIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.octet >= self.bitmap.len() { return None }
            else {
                if self.serves() {
                    return Some((self.octet * 8 + self.bit) as u16)
                }
                if self.bit == 7 { self.octet += 1; self.bit = 0 }
                else { self.bit += 1 }
            }
        }
    }
}
