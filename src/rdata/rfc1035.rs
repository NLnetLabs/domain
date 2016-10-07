//! Record data from [RFC 1035].
//!
//! This RFC defines the initial set of record types.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use std::{borrow, fmt, mem, ops};
use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::str::FromStr;
use ::bits::charstr::{CharStr, CharStrBuf};
use ::bits::compose::{Composable, Composer, ComposeResult};
use ::bits::name::{DName, DNameBuf, DNameSlice, ParsedDName};
use ::bits::parse::{Parser, ParseError, ParseResult};
use ::bits::rdata::{ParsedRecordData, RecordData};
use ::iana::Rtype;
use ::master::{Scanner, ScanResult, SyntaxError};
use ::utils::netdb::{ProtoEnt, ServEnt};


//------------ dname_type! --------------------------------------------------

/// A macro for implementing a record data type with a single domain name.
///
/// Implements some basic methods plus the RecordData, FlatRecordData, and
/// Display traits.
macro_rules! dname_type {
    ($target:ident, $rtype:ident, $field:ident) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $target<N: DName> {
            $field: N
        }

        impl<N: DName> $target<N> {
            pub fn new($field: N) -> Self {
                $target { $field: $field }
            }

            pub fn $field(&self) -> &N {
                &self.$field
            }

            pub fn rtype() -> Rtype { Rtype::$rtype }
        }

        impl $target<DNameBuf> {
            pub fn scan<S: Scanner>(scanner: &mut S,
                                    origin: Option<&DNameSlice>)
                                    -> ScanResult<Self> {
                scanner.scan_dname(origin).map(Self::new)
            }
        }

        impl<'a> $target<ParsedDName<'a>> {
            fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
                ParsedDName::parse(parser).map(Self::new)
            }
        }

        impl<N: DName> RecordData for $target<N> {
            fn rtype(&self) -> Rtype { Rtype::$rtype }

            fn compose<C: AsMut<Composer>>(&self, target: C)
                                        -> ComposeResult<()> {
                self.$field.compose_compressed(target)
            }
        }

        impl<'a> ParsedRecordData<'a> for $target<ParsedDName<'a>> {
            fn parse(rtype: Rtype, parser: &mut Parser<'a>)
                     -> ParseResult<Option<Self>> {
                if rtype == Rtype::$rtype {
                    $target::parse_always(parser).map(Some)
                }
                else { Ok(None) }
            }
        }

        impl<N: DName> fmt::Display for $target<N> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(&self.$field, f)
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
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

    pub fn rtype() -> Rtype { Rtype::A }

    fn parse_always(parser: &mut Parser) -> ParseResult<Self> {
        Ok(A::new(Ipv4Addr::new(try!(parser.parse_u8()),
                                try!(parser.parse_u8()),
                                try!(parser.parse_u8()),
                                try!(parser.parse_u8()))))
    }

    pub fn scan<S: Scanner>(scanner: &mut S, _origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        scanner.scan_str_phrase(|slice| {
            let addr = try!(Ipv4Addr::from_str(slice));
            Ok(A::new(addr))
        })
    }
}

impl RecordData for A {
    fn rtype(&self) -> Rtype { A::rtype() }
    
    fn compose<C: AsMut<Composer>>(&self, mut target: C)
                                   -> ComposeResult<()> {
        for i in &self.addr.octets() {
            try!(target.as_mut().compose_u8(*i))
        }
        Ok(())
    }
}

impl<'a> ParsedRecordData<'a> for A {
    fn parse(rtype: Rtype, parser: &mut Parser) -> ParseResult<Option<Self>> {
        if rtype == Rtype::A { A::parse_always(parser).map(Some) }
        else { Ok(None) }
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
dname_type!(Cname, Cname, cname);


//------------ Hinfo --------------------------------------------------------

/// Hinfo record data.
///
/// Hinfo records are used to acquire general information about a host,
/// specifically the CPU type and operating system type.
///
/// The Hinfo type is defined in RFC 1035, section 3.3.2.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hinfo<C: AsRef<CharStr>> {
    cpu: C,
    os: C
}

impl<C: AsRef<CharStr>> Hinfo<C> {
    /// Creates a new Hinfo record data from the components.
    pub fn new(cpu: C, os: C) -> Self {
        Hinfo{cpu: cpu, os: os}
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &C {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &C {
        &self.os
    }

    pub fn rtype() -> Rtype { Rtype::Hinfo }
}

impl<'a> Hinfo<&'a CharStr> {
    fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Ok(Self::new(try!(CharStr::parse(parser)),
                     try!(CharStr::parse(parser))))
    }
}

impl Hinfo<CharStrBuf> {
    pub fn scan<S: Scanner>(scanner: &mut S, _origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        Ok(Self::new(try!(CharStrBuf::scan(scanner)),
                     try!(CharStrBuf::scan(scanner))))
    }
}

impl<S: AsRef<CharStr>> RecordData for Hinfo<S> {
    fn rtype(&self) -> Rtype { Rtype::Hinfo }

    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        try!(self.cpu.as_ref().compose(target.as_mut()));
        self.os.as_ref().compose(target.as_mut())
    }
}

impl<'a> ParsedRecordData<'a> for Hinfo<&'a CharStr> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Hinfo { Hinfo::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl<S: AsRef<CharStr>> fmt::Display for Hinfo<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.cpu.as_ref(), self.os.as_ref())
    }
}

//------------ Mb -----------------------------------------------------------

/// MB record data.
///
/// The experimental MB record specifies a host that serves a mailbox.
///
/// The MB record type is defined in RFC 1035, section 3.3.3.
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
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Minfo<N: DName> {
    rmailbx: N,
    emailbx: N,
}

impl<N: DName> Minfo<N> {
    /// Creates a new Minfo record data from the components.
    pub fn new(rmailbx: N, emailbx: N) -> Self {
        Minfo { rmailbx: rmailbx, emailbx: emailbx }
    }

    /// The responsible mail box.
    ///
    /// The domain name specifies the mailbox which is responsible for the
    /// mailing list or mailbox. If this domain name is the root, the owner
    /// of the Minfo record is responsible for itself.
    pub fn rmailbx(&self) -> &N {
        &self.rmailbx
    }

    /// The error mail box.
    ///
    /// The domain name specifies a mailbox which is to receive error
    /// messages related to the mailing list or mailbox specified by the
    /// owner of the record. If this is the root domain name, errors should
    /// be returned to the sender of the message.
    pub fn emailbx(&self) -> &N {
        &self.emailbx
    }
}

impl<'a> Minfo<ParsedDName<'a>> {
    fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Ok(Minfo::new(try!(ParsedDName::parse(parser)),
                      try!(ParsedDName::parse(parser))))
    }
}

impl Minfo<DNameBuf> {
    pub fn scan<S: Scanner>(scanner: &mut S, origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        Ok(Self::new(try!(DNameBuf::scan(scanner, origin)),
                     try!(DNameBuf::scan(scanner, origin))))
    }
}

impl<N: DName> RecordData for Minfo<N> {
    fn rtype(&self) -> Rtype { Rtype::Minfo }

    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        try!(self.rmailbx.compose(target.as_mut()));
        self.emailbx.compose(target.as_mut())
    }
}

impl<'a> ParsedRecordData<'a> for Minfo<ParsedDName<'a>> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Minfo { Minfo::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl<N: DName> fmt::Display for Minfo<N> {
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
dname_type!(Mr, Mr, newname);


//------------ Mx -----------------------------------------------------------

/// Mx record data.
///
/// The Mx record specifies a host willing to serve as a mail exchange for
/// the owner name.
///
/// The Mx record type is defined in RFC 1035, section 3.3.9.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Mx<N: DName> {
    preference: u16,
    exchange: N,
}

impl<N: DName> Mx<N> {
    /// Creates a new Mx record data from the components.
    pub fn new(preference: u16, exchange: N) -> Self {
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
    pub fn exchange(&self) -> &N {
        &self.exchange
    }
}

impl<'a> Mx<ParsedDName<'a>> {
    fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Ok(Self::new(try!(parser.parse_u16()),
                     try!(ParsedDName::parse(parser))))
    }
}

impl Mx<DNameBuf> {
    pub fn scan<S: Scanner>(scanner: &mut S, origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        Ok(Self::new(try!(scanner.scan_u16()),
                     try!(DNameBuf::scan(scanner, origin))))
    }
}

impl<N: DName> RecordData for Mx<N> {
    fn rtype(&self) -> Rtype { Rtype::Mx }

    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        try!(target.as_mut().compose_u16(self.preference));
        self.exchange.compose(target)
    }
}

impl<'a> ParsedRecordData<'a> for Mx<ParsedDName<'a>> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Mx { Mx::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl<N: DName> fmt::Display for Mx<N> {
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
dname_type!(Ns, Ns, nsdname);


//------------ Null ---------------------------------------------------------

/// Null record data.
///
/// Null records can contain whatever data. They are experimental and not
/// allowed in master files.
///
/// The Null record type is defined in RFC 1035, section 3.3.10.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Null<D: AsRef<[u8]>> {
    data: D
}

impl<D: AsRef<[u8]>> Null<D> {
    /// Creates new, empty owned Null record data.
    pub fn new(data: D) -> Self {
        Null { data: data }
    }

    /// The raw content of the record.
    pub fn data(&self) -> &[u8] {
        &self.data.as_ref()
    }
}

impl<'a> Null<&'a [u8]> {
    fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
        let len = parser.remaining();
        parser.parse_bytes(len).map(Null::new)
    }
}

impl<D: AsRef<[u8]>> RecordData for Null<D> {
    fn rtype(&self) -> Rtype { Rtype::Null }

    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        target.as_mut().compose_bytes(&self.data())
    }
}

impl<'a> ParsedRecordData<'a> for Null<&'a [u8]> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Null { Null::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl<D: AsRef<[u8]>> fmt::Display for Null<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "\\# {} ", self.data().len()));
        let mut iter = self.data().iter();
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
dname_type!(Ptr, Ptr, ptrdname);


//------------ Soa ----------------------------------------------------------

/// Soa record data.
///
/// Soa records mark the top of a zone and contain information pertinent for
/// name server maintenance operations.
///
/// The Soa record type is defined in RFC 1035, section 3.3.13.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Soa<N: DName> {
    mname: N,
    rname: N,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32
}

impl<N: DName> Soa<N> {
    /// Creates new Soa record data from content.
    pub fn new(mname: N, rname: N, serial: u32,
               refresh: u32, retry: u32, expire: u32, minimum: u32) -> Self {
        Soa { mname: mname, rname: rname, serial: serial,
              refresh: refresh, retry: retry, expire: expire,
              minimum: minimum }
    }

    /// The primary name server for the zone.
    pub fn mname(&self) -> &N {
        &self.mname
    }

    /// The mailbox for the person responsible for this zone.
    pub fn rname(&self) -> &N {
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
}

impl<'a> Soa<ParsedDName<'a>> {
    fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Ok(Self::new(try!(ParsedDName::parse(parser)),
                     try!(ParsedDName::parse(parser)),
                     try!(parser.parse_u32()),
                     try!(parser.parse_u32()),
                     try!(parser.parse_u32()),
                     try!(parser.parse_u32()),
                     try!(parser.parse_u32())))
    }
}

impl Soa<DNameBuf> {
    pub fn scan<S: Scanner>(scanner: &mut S, origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        Ok(Self::new(try!(DNameBuf::scan(scanner, origin)),
                     try!(DNameBuf::scan(scanner, origin)),
                     try!(scanner.scan_u32()),
                     try!(scanner.scan_u32()),
                     try!(scanner.scan_u32()),
                     try!(scanner.scan_u32()),
                     try!(scanner.scan_u32())))
    }
}

impl<N: DName> RecordData for Soa<N> {
    fn rtype(&self) -> Rtype { Rtype::Soa }

    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        try!(self.mname.compose(target.as_mut()));
        try!(self.rname.compose(target.as_mut()));
        try!(self.serial.compose(target.as_mut()));
        try!(self.refresh.compose(target.as_mut()));
        try!(self.retry.compose(target.as_mut()));
        try!(self.expire.compose(target.as_mut()));
        try!(self.minimum.compose(target.as_mut()));
        Ok(())
    }
}

impl<'a> ParsedRecordData<'a> for Soa<ParsedDName<'a>> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Soa { Soa::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl<N: DName> fmt::Display for Soa<N> {
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
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Txt<T: AsRef<[u8]>> {
    text: T,
}

impl<T: AsRef<[u8]>> Txt<T> {
    /// Creates a new Txt record from content.
    pub fn new(text: T) -> Self {
        Txt { text: text }
    }

    /// Returns an iterator over the text items.
    ///
    /// The Txt format contains one or more length-delimited byte strings.
    /// This method returns an iterator over each of them.
    pub fn iter(&self) -> TxtIter {
        TxtIter::new(self.text.as_ref())
    }

    /// Returns the text content.
    ///
    /// If the raw content is only a single character-string, returns a
    /// borrow else creates an owned vec by concatenating all the parts.
    pub fn text(&self) -> Cow<[u8]> {
        let text = self.text.as_ref();
        if text.len() == 0 {
            Cow::Borrowed(b"")
        }
        else if (text[0] as usize) == text.len() - 1 {
            Cow::Borrowed(&text[1..])
        }
        else {
            let mut res = Vec::new();
            for item in self.iter() {
                res.extend_from_slice(&item)
            }
            Cow::Owned(res)
        }
    }
}

impl<'a> Txt<&'a [u8]> {
    fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
        let len = parser.remaining();
        let bytes = try!(parser.parse_bytes(len));
        let mut tmp = bytes;
        while !tmp.is_empty() {
            let len = tmp[0] as usize;
            if len > tmp.len() {
                return Err(ParseError::FormErr)
            }
            tmp = &tmp[len..];
        }
        return Ok(Self::new(bytes))
    }
}

impl Txt<Vec<u8>> {
    pub fn scan<S: Scanner>(scanner: &mut S, _origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        let mut target = Vec::new();
        let mut len = 0;
        let mut pos = target.len();
        target.push(0);
        try!(scanner.scan_phrase_bytes(|ch, _| {
            target.push(ch);
            if len == 254 {
                target[pos] = 255;
                len = 0;
                pos = target.len();
                target.push(0);
            }
            else {
                len += 1
            }
            Ok(())
        }));
        target[pos] = len;
        Ok(Self::new(target))
    }
}

impl<T: AsRef<[u8]>> RecordData for Txt<T> {
    fn rtype(&self) -> Rtype { Rtype::Txt }

    fn compose<C: AsMut<Composer>>(&self, target: C) -> ComposeResult<()> {
        self.text.as_ref().compose(target)
    }
}

impl<'a> ParsedRecordData<'a> for Txt<&'a [u8]> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Txt { Txt::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Txt<T> {
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
    type Item = &'a CharStr;

    fn next(&mut self) -> Option<Self::Item> {
        self.text.split_first().map(|(len, tail)| {
            let len = *len as usize;
            if tail.len() <= len {
                self.text = b"";
                CharStr::from_bytes(tail).unwrap()
            }
            else {
                let (head, tail) = tail.split_at(len);
                self.text = tail;
                CharStr::from_bytes(head).unwrap()
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wks<B: AsRef<WksBitmap>> {
    address: Ipv4Addr,
    protocol: u8,
    bitmap: B,
}

impl<B: AsRef<WksBitmap>> Wks<B> {
    /// Creates a new record data from components.
    pub fn new(address: Ipv4Addr, protocol: u8, bitmap: B) -> Self {
        Wks { address: address, protocol: protocol, bitmap: bitmap }
    }

    /// The IPv4 address of the host this record refers to.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// The protocol number of the protocol this record refers to.
    ///
    /// This will typically be `6` for TCP or `17` for UDP.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// A bitmap indicating the ports where service is being provided.
    pub fn bitmap(&self) -> &WksBitmap {
        self.bitmap.as_ref()
    }

    /// Returns whether a certain service is being provided.
    pub fn serves(&self, port: u16) -> bool {
        self.bitmap.as_ref().serves(port)
    }

    /// Returns an iterator over the served ports.
    pub fn iter(&self) -> WksIter {
        self.bitmap.as_ref().iter()
    }
}

impl<'a> Wks<&'a WksBitmap> {
    fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
        let addr = Ipv4Addr::new(try!(parser.parse_u8()),
                                 try!(parser.parse_u8()),
                                 try!(parser.parse_u8()),
                                 try!(parser.parse_u8()));
        let proto = try!(parser.parse_u8());
        let len = parser.remaining();
        let bitmap = WksBitmap::from_bytes(try!(parser.parse_bytes(len)));
        Ok(Wks::new(addr, proto, bitmap))
    }
}

impl Wks<WksBitmapBuf> {
    pub fn scan<S: Scanner>(scanner: &mut S, origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        let a = try!(A::scan(scanner, origin));
        let proto = try!(scanner.scan_str_phrase(|s| {
            if let Some(ent) = ProtoEnt::by_name(s) {
                Ok(ent.proto)
            }
            else if let Ok(number) = u8::from_str_radix(s, 10) {
                Ok(number)
            }
            else {
                Err(SyntaxError::UnknownProto(s.into()))
            }
        }));

        let mut bitmap = WksBitmapBuf::new();
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
        Ok(Self::new(a.addr(), proto, bitmap))
    }
}

impl<B: AsRef<WksBitmap>> RecordData for Wks<B> {
    fn rtype(&self) -> Rtype { Rtype::Wks }

    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        for i in &self.address.octets() {
            try!(i.compose(target.as_mut()))
        }
        try!(self.protocol.compose(target.as_mut()));
        self.bitmap.as_ref().as_bytes().compose(target)
    }
}

impl<'a> ParsedRecordData<'a> for Wks<&'a WksBitmap> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Wks { Wks::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl<B: AsRef<WksBitmap>> fmt::Display for Wks<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "{} {}", self.address, self.protocol));
        for port in self.iter() {
            try!(write!(f, " {}", port));
        }
        Ok(())
    }
}


//------------ WksBitmap -----------------------------------------------------

#[derive(Debug)]
pub struct WksBitmap {
    inner: [u8]
}


impl WksBitmap {
    pub fn from_bytes(bytes: &[u8]) -> &Self {
        unsafe { mem::transmute(bytes) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn iter(&self) -> WksIter {
        WksIter::new(&self.inner)
    }

    /// Returns whether a certain service is being provided.
    pub fn serves(&self, port: u16) -> bool {
        let (octet, bit) = WksBitmap::port_location(port);
        match self.inner.get(octet) {
            Some(x) => (x >> bit) > 0,
            None => false
        }
    }

    /// Translates a port number to where it’ll be in the bitmap.
    ///
    /// Returns a pair of the index in the bytes slice and the bit number in
    /// that slice.
    fn port_location(port: u16) -> (usize, usize) {
        ((port / 8) as usize, (port % 8) as usize)
    }
}


//--- From

impl<'a> From<&'a [u8]> for &'a WksBitmap {
    fn from(x: &'a [u8]) -> Self {
        WksBitmap::from_bytes(x)
    }
}


//--- AsRef

impl AsRef<WksBitmap> for WksBitmap {
    fn as_ref(&self) -> &Self {
        self
    }
}


//--- PartialEq

impl PartialEq for WksBitmap {
    fn eq(&self, other: &Self) -> bool {
        let mut s = &self.inner;
        let mut o = &other.inner;
        while let Some((&0, head)) = s.split_last() { s = head }
        while let Some((&0, head)) = o.split_last() { o = head }
        s == o
    }
}

impl<T: AsRef<WksBitmap>> PartialEq<T> for WksBitmap {
    fn eq(&self, other: &T) -> bool {
        self.eq(other.as_ref())
    }
}

impl Eq for WksBitmap { }


//------------ WksBitmapBuf --------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct WksBitmapBuf {
    inner: Vec<u8>,
}


impl WksBitmapBuf {
    pub fn new() -> Self {
        WksBitmapBuf::from_vec(Vec::new())
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        WksBitmapBuf{inner: vec}
    }

    /// Enables or disables the given service.
    pub fn set_serves(&mut self, port: u16, enable: bool) {
        let (octet, bit) = WksBitmap::port_location(port);
        if self.inner.len() <= octet {
            self.inner.resize(octet + 1, 0);
        }
        if enable {
            self.inner[octet] |= 1 << bit
        }
        else {
            self.inner[octet] &= 0xFF ^ (1 << bit)
        }
    }
}


//--- Deref, Borrow, AsRef

impl ops::Deref for WksBitmapBuf {
    type Target = WksBitmap;

    fn deref(&self) -> &Self::Target {
        WksBitmap::from_bytes(&self.inner)
    }
}

impl borrow::Borrow<WksBitmap> for WksBitmapBuf {
    fn borrow(&self) -> &WksBitmap {
        self
    }
}

impl AsRef<WksBitmap> for WksBitmapBuf {
    fn as_ref(&self) -> &WksBitmap {
        self
    }
}


//--- PartialEq, Eq

impl<T: AsRef<WksBitmap>> PartialEq<T> for WksBitmapBuf {
    fn eq(&self, other: &T) -> bool {
        other.as_ref().eq(self)
    }
}

impl Eq for WksBitmapBuf { }


//------------ WksIter -------------------------------------------------------

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


//============ Type Aliases =================================================

pub mod parsed {
    use ::bits::{CharStr, ParsedDName};

    pub type A = super::A;
    pub type Cname<'a> = super::Cname<ParsedDName<'a>>;
    pub type Hinfo<'a> = super::Hinfo<&'a CharStr>;
    pub type Mb<'a> = super::Mb<ParsedDName<'a>>;
    pub type Md<'a> = super::Md<ParsedDName<'a>>;
    pub type Mf<'a> = super::Mf<ParsedDName<'a>>;
    pub type Mg<'a> = super::Mg<ParsedDName<'a>>;
    pub type Minfo<'a> = super::Minfo<ParsedDName<'a>>;
    pub type Mr<'a> = super::Mr<ParsedDName<'a>>;
    pub type Mx<'a> = super::Mx<ParsedDName<'a>>;
    pub type Ns<'a> = super::Ns<ParsedDName<'a>>;
    pub type Ptr<'a> = super::Ptr<ParsedDName<'a>>;
    pub type Soa<'a> = super::Soa<ParsedDName<'a>>;
    pub type Txt<'a> = super::Txt<&'a [u8]>;
    pub type Wks<'a> = super::Wks<&'a super::WksBitmap>;
}

pub mod owned {
    use ::bits::{CharStrBuf, DNameBuf};

    pub type A = super::A;
    pub type Cname = super::Cname<DNameBuf>;
    pub type Hinfo = super::Hinfo<CharStrBuf>;
    pub type Mb = super::Mb<DNameBuf>;
    pub type Md = super::Md<DNameBuf>;
    pub type Mf = super::Mf<DNameBuf>;
    pub type Mg = super::Mg<DNameBuf>;
    pub type Minfo = super::Minfo<DNameBuf>;
    pub type Mr = super::Mr<DNameBuf>;
    pub type Mx = super::Mx<DNameBuf>;
    pub type Ns = super::Ns<DNameBuf>;
    pub type Ptr = super::Ptr<DNameBuf>;
    pub type Soa = super::Soa<DNameBuf>;
    pub type Txt = super::Txt<DNameBuf>;
    pub type Wks = super::Wks<DNameBuf>;
}
