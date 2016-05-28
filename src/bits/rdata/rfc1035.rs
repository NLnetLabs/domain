//! Record data from RFC 1035.
//!
//! This RFC defines the initial set of record types.

use std::borrow::Cow;
use std::fmt;
use std::net::Ipv4Addr;
use super::super::compose::ComposeBytes;
use super::super::charstr::CharStr;
use super::super::error::{ComposeResult, ParseResult};
use super::super::iana::RRType;
use super::super::name::DName;
use super::super::octets::Octets;
use super::super::parse::ParseBytes;
use super::traits::RecordData;


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

            pub fn $field(&self) -> &DName<'a> {
                &self.$field
            }
        }

        impl<'a> RecordData<'a> for $target<'a> {
            fn rtype(&self) -> RRType { RRType::$rtype }

            fn compose<C: ComposeBytes>(&self, target: &mut C)
                                        -> ComposeResult<()> {
                target.push_dname_compressed(&self.$field)
            }
        
            fn parse<P>(rtype: RRType, parser: &mut P)
                        -> ParseResult<Option<Self>>
                     where P: ParseBytes<'a> {
                if rtype != RRType::$rtype { Ok(None) }
                else { Ok(Some($target::new(try!(parser.parse_dname())))) }
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
/// A records convey the IPv4 address of a host.
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

    pub fn addr(&self) -> &Ipv4Addr { &self.addr }
    pub fn addr_mut(&mut self) -> &mut Ipv4Addr { &mut self.addr }
}

impl<'a> RecordData<'a> for A {
    fn rtype(&self) -> RRType { RRType::A }
    
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.addr.octets().iter() {
            try!(target.push_u8(*i))
        }
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        if rtype != RRType::A { return Ok(None) }
        Ok(Some(A::new(Ipv4Addr::new(try!(parser.parse_u8()),
                                     try!(parser.parse_u8()),
                                     try!(parser.parse_u8()),
                                     try!(parser.parse_u8())))))
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}


//------------ CName --------------------------------------------------------

/// CNAME record data.
///
/// The CNAME record specifies the canonical or primary name for domain
/// name alias.
///
/// The CNAME type is defined in RFC 1035, section 3.3.1.
#[derive(Clone, Debug, PartialEq)]
pub struct CName<'a> {
    cname: DName<'a>
}

dname_type!(CName, CNAME, cname);


//------------ HInfo --------------------------------------------------------

/// HINFO record data.
///
/// HINFO records are used to acquire general information about a host,
/// specifically the CPU type and operating system type.
///
/// The HINFO type is defined in RFC 1035, section 3.3.2.
#[derive(Clone, Debug, PartialEq)]
pub struct HInfo<'a> {
    cpu: CharStr<'a>,
    os: CharStr<'a>
}

impl<'a> HInfo<'a> {
    /// Creates a new HINFO record data from the components.
    pub fn new(cpu: CharStr<'a>, os: CharStr<'a>) -> Self {
        HInfo { cpu: cpu, os: os }
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &CharStr<'a> {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &CharStr<'a> {
        &self.os
    }
}

impl<'a> RecordData<'a> for HInfo<'a> {
    fn rtype(&self) -> RRType { RRType::HINFO }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        try!(target.push_charstr(&self.cpu));
        try!(target.push_charstr(&self.os));
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        if rtype != RRType::HINFO { Ok(None) }
        else {
            Ok(Some(HInfo::new(try!(parser.parse_charstr()),
                               try!(parser.parse_charstr()))))
        }
    }
}


impl<'a> fmt::Display for HInfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}


//------------ MB -----------------------------------------------------------

/// MB record data.
///
/// The experimental MB record specifies a host that serves a mailbox.
///
/// The MB record type is defined in RFC 1035, section 3.3.3.
#[derive(Clone, Debug, PartialEq)]
pub struct MB<'a> {
    madname: DName<'a>
}

dname_type!(MB, MB, madname);


//------------ MD -----------------------------------------------------------

/// MD record data.
///
/// The MD record specifices a host which has a mail agent for
/// the domain which should be able to deliver mail for the domain.
/// 
/// The MD record is obsolete. It is recommended to either reject the record
/// or convert them into an MX record at preference 0.
///
/// The MD record type is defined in RFC 1035, section 3.3.4.
#[derive(Clone, Debug, PartialEq)]
pub struct MD<'a> {
    madname: DName<'a>
}

dname_type!(MD, MD, madname);


//------------ MF -----------------------------------------------------------

/// MF record data.
///
/// The MF record specifices a host which has a mail agent for
/// the domain which will be accept mail for forwarding to the domain.
/// 
/// The MF record is obsolete. It is recommended to either reject the record
/// or convert them into an MX record at preference 10.
///
/// The MF record type is defined in RFC 1035, section 3.3.5.
#[derive(Clone, Debug, PartialEq)]
pub struct MF<'a> {
    madname: DName<'a>
}

dname_type!(MF, MF, madname);


//------------ MG -----------------------------------------------------------

/// MG record data.
///
/// The MG record specifices a mailbox which is a member of the mail group
/// specified by the domain name.
/// 
/// The MG record is experimental.
///
/// The MG record type is defined in RFC 1035, section 3.3.6.
#[derive(Clone, Debug, PartialEq)]
pub struct MG<'a> {
    madname: DName<'a>
}

dname_type!(MG, MG, madname);


//------------ MINFO --------------------------------------------------------

/// MINFO record data.
///
/// The MINFO record specifies a mailbox which is responsible for the mailing
/// list or mailbox and a mailbox that receives error messages related to the
/// list or box.
///
/// The MINFO record is experimental.
///
/// The MINFO record type is defined in RFC 1035, section 3.3.7.
#[derive(Clone, Debug, PartialEq)]
pub struct MInfo<'a> {
    rmailbx: DName<'a>,
    emailbx: DName<'a>
}

impl<'a> MInfo<'a> {
    /// Creates a new MINFO record data from the components.
    pub fn new(rmailbx: DName<'a>, emailbx: DName<'a>) -> Self {
        MInfo { rmailbx: rmailbx, emailbx: emailbx }
    }

    /// The responsible mail box.
    ///
    /// The domain name specifies the mailbox which is responsible for the
    /// mailing list or mailbox. If this domain name is the root, the owner
    /// of the MINFO record is responsible for itself.
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
}

impl<'a> RecordData<'a> for MInfo<'a> {
    fn rtype(&self) -> RRType { RRType::MINFO }

    fn compose<C: ComposeBytes>(&self, target: &mut C)
                                -> ComposeResult<()> {
        try!(target.push_dname(&self.rmailbx));
        try!(target.push_dname(&self.emailbx));
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        if rtype != RRType::MINFO { Ok(None) }
        else {
            Ok(Some(MInfo::new(try!(parser.parse_dname()),
                               try!(parser.parse_dname()))))
        }
    }
}

impl<'a> fmt::Display for MInfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.rmailbx, self.emailbx)
    }
}


//------------ MR -----------------------------------------------------------

/// MR record data.
///
/// The MR record specifices a mailbox which is the proper rename of the
/// specified mailbox.
/// 
/// The MR record is experimental.
///
/// The MR record type is defined in RFC 1035, section 3.3.8.
#[derive(Clone, Debug, PartialEq)]
pub struct MR<'a> {
    newname: DName<'a>
}

dname_type!(MR, MR, newname);


//------------ MX -----------------------------------------------------------

/// MX record data.
///
/// The MX record specifies a host willing to serve as a mail exchange for
/// the owner name.
///
/// The MX record type is defined in RFC 1035, section 3.3.9.
#[derive(Clone, Debug, PartialEq)]
pub struct MX<'a> {
    preference: u16,
    exchange: DName<'a>,
}

impl<'a> MX<'a> {
    /// Creates a new MX record data from the components.
    pub fn new(preference: u16, exchange: DName<'a>) -> Self {
        MX { preference: preference, exchange: exchange }
    }

    /// The preference for this record.
    ///
    /// Defines an order if there are several MX records for the same owner.
    /// Lower values are preferred.
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// The name of the host that is the exchange.
    pub fn exchange(&self) -> &DName<'a> {
        &self.exchange
    }
}

impl<'a> RecordData<'a> for MX<'a> {
    fn rtype(&self) -> RRType { RRType::MX }

    fn compose<C: ComposeBytes>(&self, target: &mut C)
                                -> ComposeResult<()> {
        try!(target.push_u16(self.preference));
        try!(target.push_dname(&self.exchange));
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        if rtype != RRType::MX { Ok(None) }
        else {
            Ok(Some(MX::new(try!(parser.parse_u16()),
                            try!(parser.parse_dname()))))
        }
    }
}

impl<'a> fmt::Display for MX<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}


//------------ NS -----------------------------------------------------------

/// NS record data.
///
/// NS records specify hosts that are authoritative for a class and domain.
///
/// The NS record type is defined in RFC 1035, section 3.3.11.
#[derive(Clone, Debug, PartialEq)]
pub struct NS<'a> {
    nsdname: DName<'a>
}

dname_type!(NS, NS, nsdname);


//------------ Null ---------------------------------------------------------

/// NULL record data.
///
/// NULL records can contain whatever data. They are experimental, not
/// allowed in master files.
///
/// The NULL record type is defined in RFC 1035, section 3.3.10.
#[derive(Clone, Debug, PartialEq)]
pub struct Null<'a> {
    data: Octets<'a>
}

impl<'a> Null<'a> {
    /// Creates new, empty owned NULL record data.
    pub fn new(data: Octets<'a>) -> Self {
        Null { data: data }
    }

    /// The raw content of the record.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<'a> RecordData<'a> for Null<'a> {
    fn rtype(&self) -> RRType { RRType::NULL }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_octets(&self.data)
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        if rtype != RRType::NULL { Ok(None) }
        else {
            let len = parser.left();
            Ok(Some(Null::new(try!(parser.parse_octets(len)))))
        }
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

dname_type!(Ptr, PTR, ptrdname);


//------------ SOA ----------------------------------------------------------

/// SOA record data.
///
/// SOA records mark the top of a zone and contain information pertinent for
/// name server maintenance operations.
///
/// The SOA record type is defined in RFC 1035, section 3.3.13.
#[derive(Clone, Debug, PartialEq)]
pub struct SOA<'a> {
    mname: DName<'a>,
    rname: DName<'a>,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32
}

impl<'a> SOA<'a> {
    /// Creates new SOA record data from content.
    pub fn new(mname: DName<'a>, rname: DName<'a>, serial: u32,
               refresh: u32, retry: u32, expire: u32, minimum: u32) -> Self {
        SOA { mname: mname, rname: rname, serial: serial,
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
}

impl<'a> RecordData<'a> for SOA<'a> {
    fn rtype(&self) -> RRType { RRType::SOA }

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

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        if rtype != RRType::SOA { Ok(None) }
        else {
            Ok(Some(SOA::new(try!(parser.parse_dname()),
                             try!(parser.parse_dname()),
                             try!(parser.parse_u32()),
                             try!(parser.parse_u32()),
                             try!(parser.parse_u32()),
                             try!(parser.parse_u32()),
                             try!(parser.parse_u32()))))
        }
    }
}

impl<'a> fmt::Display for SOA<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {}", self.mname, self.rname,
               self.serial, self.refresh, self.retry, self.expire,
               self.minimum)
    }
}


//------------ Txt ----------------------------------------------------------

/// TXT record data.
///
/// TXT records hold descriptive text.
///
/// The TXT record type is defined in RFC 1035, section 3.3.14.
#[derive(Clone, Debug, PartialEq)]
pub struct Txt<'a> {
    text: Cow<'a, [u8]>
}

impl<'a> Txt<'a> {
    /// Creates a new TXT record from content.
    pub fn new(text: Cow<'a, [u8]>) -> Self {
        Txt { text: text }
    }

    /// Returns an iterator over the text items.
    ///
    /// The TXT format contains one or more length-delimited byte strings.
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
}

impl<'a> RecordData<'a> for Txt<'a> {
    fn rtype(&self) -> RRType { RRType::TXT }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_bytes(&self.text)
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        if rtype != RRType::TXT { Ok(None) }
        else {
            let len = parser.left();
            Ok(Some(Txt::new(Cow::Borrowed(try!(parser.parse_bytes(len))))))
        }
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

/// An iterator over the character strings of a TXT record.
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


//------------ WKS ----------------------------------------------------------

/// WKS record data.
///
/// WKS records describe the well-known services supported by a particular
/// protocol on a particular internet address.
///
/// The WKS record type is defined in RFC 1035, section 3.4.2.
#[derive(Clone, Debug, PartialEq)]
pub struct WKS<'a> {
    address: Ipv4Addr,
    protocol: u8,
    bitmap: Cow<'a, [u8]>
}

impl<'a> WKS<'a> {
    /// Creates a new record data from components.
    pub fn new(address: Ipv4Addr, protocol: u8, bitmap: Cow<'a, [u8]>)
               -> Self {
        WKS { address: address, protocol: protocol, bitmap: bitmap }
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
    pub fn bitmap(&self) -> &[u8] {
        &self.bitmap
    }

    /// Returns whether a certain service is being provided.
    pub fn serves(&self, port: u16) -> bool {
        let octet = (port / 8) as usize;
        let bit = (port % 8) as usize;
        if self.bitmap.len() <= octet { false }
        else { (self.bitmap[octet] >> bit) > 0 }
    }

    /// Returns an iterator over the served ports.
    pub fn iter(&self) -> WksIter {
        WksIter::new(&self.bitmap)
    }
}


impl<'a> RecordData<'a> for WKS<'a> {
    fn rtype(&self) -> RRType { RRType::WKS }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.address.octets().iter() {
            try!(target.push_u8(*i))
        }
        try!(target.push_u8(self.protocol));
        target.push_bytes(&self.bitmap)
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        if rtype != RRType::WKS { Ok(None) }
        else {
            let addr = Ipv4Addr::new(try!(parser.parse_u8()),
                                     try!(parser.parse_u8()),
                                     try!(parser.parse_u8()),
                                     try!(parser.parse_u8()));
            let proto = try!(parser.parse_u8());
            let len = parser.left();
            let bitmap = Cow::Borrowed(try!(parser.parse_bytes(len)));
            Ok(Some(WKS::new(addr, proto, bitmap)))
        }
    }
}

impl<'a> fmt::Display for WKS<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "{} {}", self.address, self.protocol));
        for port in self.iter() {
            try!(write!(f, " {}", port));
        }
        Ok(())
    }
}
 

//--- WksIter

/// An iterator over the services active in a WKS record.
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
