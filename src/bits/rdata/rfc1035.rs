//! Record data from RFC 1035.
//!
//! This RFC defines the initial set of record types.

use std::borrow::Cow;
use std::fmt;
use std::net::Ipv4Addr;
use super::super::compose::ComposeBytes;
use super::super::cstring::CStringRef;
use super::super::error::{ComposeResult, ParseResult};
use super::super::flavor::{FlatFlavor, Flavor};
use super::super::iana::RRType;
use super::super::octets::Octets;
use super::super::parse::{ParseBytes, ParseFlavor, SliceParser};
use super::traits::{FlatRecordData, RecordData};


//------------ dname_type! --------------------------------------------------

/// A macro for implementing a record data type with a single domain name.
///
/// Implements some basic methods plus the RecordData, FlatRecordData, and
/// Display traits.
macro_rules! dname_type {
    ($target:ident, $rtype:ident, $field:ident) => {
        impl<F: Flavor> $target<F> {
            pub fn new($field: F::DName) -> Self {
                $target { $field: $field }
            }

            pub fn $field(&self) -> &F::DName {
                &self.$field
            }
        }

        impl<F: Flavor> RecordData<F> for $target<F> {
            fn rtype(&self) -> RRType { RRType::$rtype }

            fn compose<C: ComposeBytes>(&self, target: &mut C)
                                        -> ComposeResult<()> {
                target.push_dname_compressed(&self.$field)
            }
        }

        impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for $target<F> {
            fn parse<P>(rtype: RRType, parser: &mut P)
                        -> ParseResult<Option<Self>>
                     where P: ParseFlavor<'a, F> {
                if rtype != RRType::$rtype { Ok(None) }
                else { Ok(Some($target::new(try!(parser.parse_dname())))) }
            }
        }

        impl<F: Flavor> fmt::Display for $target<F> {
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
#[derive(Clone, Debug)]
pub struct A {
    addr: Ipv4Addr,
}

impl A {
    /// Creates a new A record data from an IPv4 address.
    pub fn new(addr: Ipv4Addr) -> A {
        A { addr: addr }
    }

    pub fn addr(&self) -> &Ipv4Addr { &self.addr }
    pub fn addr_mut(&mut self) -> &mut Ipv4Addr { &mut self.addr }
}

impl<F: Flavor> RecordData<F> for A {
    fn rtype(&self) -> RRType { RRType::A }
    
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.addr.octets().iter() {
            try!(target.push_u8(*i))
        }
        Ok(())
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for A {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
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
#[derive(Clone, Debug)]
pub struct CName<F: Flavor> {
    cname: F::DName
}

dname_type!(CName, CNAME, cname);


//------------ HInfo --------------------------------------------------------

/// HINFO record data.
///
/// HINFO records are used to acquire general information about a host,
/// specifically the CPU type and operating system type.
///
/// The HINFO type is defined in RFC 1035, section 3.3.2.
#[derive(Clone, Debug)]
pub struct HInfo<F: Flavor> {
    cpu: F::CString,
    os: F::CString,
}

impl<F: Flavor> HInfo<F> {
    /// Creates a new HINFO record data from the components.
    pub fn new(cpu: F::CString, os: F::CString) -> Self {
        HInfo { cpu: cpu, os: os }
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &F::CString {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &F::CString {
        &self.os
    }
}

impl<F: Flavor> RecordData<F> for HInfo<F> {
    fn rtype(&self) -> RRType { RRType::HINFO }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        try!(target.push_cstring(&self.cpu));
        try!(target.push_cstring(&self.os));
        Ok(())
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for HInfo<F> {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::HINFO { Ok(None) }
        else {
            Ok(Some(HInfo::new(try!(parser.parse_cstring()),
                               try!(parser.parse_cstring()))))
        }
    }
}


impl<F: Flavor> fmt::Display for HInfo<F> {
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
#[derive(Clone, Debug)]
pub struct MB<F: Flavor> {
    madname: F::DName
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
#[derive(Clone, Debug)]
pub struct MD<F: Flavor> {
    madname: F::DName
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
#[derive(Clone, Debug)]
pub struct MF<F: Flavor> {
    madname: F::DName
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
#[derive(Clone, Debug)]
pub struct MG<F: Flavor> {
    madname: F::DName
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
#[derive(Clone, Debug)]
pub struct MInfo<F: Flavor> {
    rmailbx: F::DName,
    emailbx: F::DName
}

impl<F: Flavor> MInfo<F> {
    /// Creates a new MINFO record data from the components.
    pub fn new(rmailbx: F::DName, emailbx: F::DName) -> Self {
        MInfo { rmailbx: rmailbx, emailbx: emailbx }
    }

    /// The responsible mail box.
    ///
    /// The domain name specifies the mailbox which is responsible for the
    /// mailing list or mailbox. If this domain name is the root, the owner
    /// of the MINFO record is responsible for itself.
    pub fn rmailbx(&self) -> &F::DName {
        &self.rmailbx
    }

    /// The error mail box.
    ///
    /// The domain name specifies a mailbox which is to receive error
    /// messages related to the mailing list or mailbox specified by the
    /// owner of the record. If this is the root domain name, errors should
    /// be returned to the sender of the message.
    pub fn emailbx(&self) -> &F::DName {
        &self.emailbx
    }
}

impl<F: Flavor> RecordData<F> for MInfo<F> {
    fn rtype(&self) -> RRType { RRType::MINFO }

    fn compose<C: ComposeBytes>(&self, target: &mut C)
                                -> ComposeResult<()> {
        try!(target.push_dname(&self.rmailbx));
        try!(target.push_dname(&self.emailbx));
        Ok(())
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for MInfo<F> {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::MINFO { Ok(None) }
        else {
            Ok(Some(MInfo::new(try!(parser.parse_dname()),
                               try!(parser.parse_dname()))))
        }
    }
}

impl<F: Flavor> fmt::Display for MInfo<F> {
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
#[derive(Clone, Debug)]
pub struct MR<F: Flavor> {
    newname: F::DName
}

dname_type!(MR, MR, newname);


//------------ MX -----------------------------------------------------------

/// MX record data.
///
/// The MX record specifies a host willing to serve as a mail exchange for
/// the owner name.
///
/// The MX record type is defined in RFC 1035, section 3.3.9.
#[derive(Clone, Debug)]
pub struct MX<F: Flavor> {
    preference: u16,
    exchange: F::DName,
}

impl<F: Flavor> MX<F> {
    /// Creates a new MX record data from the components.
    pub fn new(preference: u16, exchange: F::DName) -> Self {
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
    pub fn exchange(&self) -> &F::DName {
        &self.exchange
    }
}

impl<F: Flavor> RecordData<F> for MX<F> {
    fn rtype(&self) -> RRType { RRType::MX }

    fn compose<C: ComposeBytes>(&self, target: &mut C)
                                -> ComposeResult<()> {
        try!(target.push_u16(self.preference));
        try!(target.push_dname(&self.exchange));
        Ok(())
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for MX<F> {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::MX { Ok(None) }
        else {
            Ok(Some(MX::new(try!(parser.parse_u16()),
                            try!(parser.parse_dname()))))
        }
    }
}

impl<F: Flavor> fmt::Display for MX<F> {
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
#[derive(Clone, Debug)]
pub struct NS<F: Flavor> {
    nsdname: F::DName
}

dname_type!(NS, NS, nsdname);


//------------ Null ---------------------------------------------------------

/// NULL record data.
///
/// NULL records can contain whatever data. They are experimental, not
/// allowed in master files.
///
/// The NULL record type is defined in RFC 1035, section 3.3.10.
#[derive(Clone, Debug)]
pub struct Null<F: Flavor> {
    data: F::Octets
}

impl<F: Flavor> Null<F> {
    /// Creates a new NULL record data from content.
    pub fn new(data: F::Octets) -> Self {
        Null { data: data }
    }

    /// The raw content of the record.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<F: Flavor> RecordData<F> for Null<F> {
    fn rtype(&self) -> RRType { RRType::NULL }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        self.data.compose(target)
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for Null<F> {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::NULL { Ok(None) }
        else {
            let len = parser.left();
            Ok(Some(Null::new(try!(parser.parse_octets(len)))))
        }
    }
}

impl<F: Flavor> fmt::Display for Null<F> {
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
#[derive(Clone, Debug)]
pub struct Ptr<F: Flavor> {
    ptrdname: F::DName
}

dname_type!(Ptr, PTR, ptrdname);


//------------ SOA ----------------------------------------------------------

/// SOA record data.
///
/// SOA records mark the top of a zone and contain information pertinent for
/// name server maintenance operations.
///
/// The SOA record type is defined in RFC 1035, section 3.3.13.
#[derive(Clone, Debug)]
pub struct SOA<F: Flavor> {
    mname: F::DName,
    rname: F::DName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32
}

impl<F: Flavor> SOA<F> {
    /// Creates a new SOA record data from content.
    pub fn new(mname: F::DName, rname: F::DName, serial: u32,
               refresh: u32, retry: u32, expire: u32, minimum: u32) -> Self {
        SOA { mname: mname, rname: rname, serial: serial,
              refresh: refresh, retry: retry, expire: expire,
              minimum: minimum }
    }

    /// The primary name server for the zone.
    pub fn mname(&self) -> &F::DName {
        &self.mname
    }

    /// The mailbox for the person responsible for this zone.
    pub fn rname(&self) -> &F::DName {
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

impl<F: Flavor> RecordData<F> for SOA<F> {
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
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for SOA<F> {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
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

impl<F: Flavor> fmt::Display for SOA<F> {
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
#[derive(Clone, Debug)]
pub struct Txt<F: Flavor> {
    text: F::Octets,
}

impl<F: Flavor> Txt<F> {
    /// Creates a new TXT record from content.
    pub fn new(text: F::Octets) -> Self {
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

impl<F: Flavor> RecordData<F> for Txt<F> {
    fn rtype(&self) -> RRType { RRType::TXT }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        self.text.compose(target)
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for Txt<F> {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::TXT { Ok(None) }
        else {
            let len = parser.left();
            let octets = try!(parser.parse_octets(len));
            {
                let mut parser = octets.parser();
                loop {
                    let len = try!(parser.parse_u8()) as usize;
                    let _ = try!(parser.parse_bytes(len));
                    if parser.left() == 0 { break }
                }
            }
            Ok(Some(Txt::new(octets)))
        }
    }
}

impl<F: Flavor> fmt::Display for Txt<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for text in self.iter() {
            try!(text.fmt(f))
        }
        Ok(())
    }
}

//--- TxtIter

/// An iterator over the character strings of a TXT record.
#[derive(Clone, Debug)]
pub struct TxtIter<'a> {
    parser: SliceParser<'a>,
}

impl<'a> TxtIter<'a> {
    fn new(slice: &'a [u8]) -> Self {
        TxtIter { parser: SliceParser::new(slice) }
    }
}

impl<'a> Iterator for TxtIter<'a> {
    type Item = CStringRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match CStringRef::parse(&mut self.parser) {
            Ok(item) => Some(item),
            Err(..) => None
        }
    }
}


//------------ WKS ----------------------------------------------------------

/// WKS record data.
///
/// WKS records describe the well-known services supported by a particular
/// protocol on a particular internet address.
///
/// The WKS record type is defined in RFC 1035, section 3.4.2.
#[derive(Clone, Debug)]
pub struct WKS<F: Flavor> {
    address: Ipv4Addr,
    protocol: u8,
    bitmap: F::Octets
}

impl<F: Flavor> WKS<F> {
    /// Creates a new record data from components.
    pub fn new(address: Ipv4Addr, protocol: u8, bitmap: F::Octets) -> Self {
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


impl<F: Flavor> RecordData<F> for WKS<F> {
    fn rtype(&self) -> RRType { RRType::WKS }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.address.octets().iter() {
            try!(target.push_u8(*i))
        }
        try!(target.push_u8(self.protocol));
        target.push_bytes(&self.bitmap)
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for WKS<F> {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::WKS { Ok(None) }
        else {
            let addr = Ipv4Addr::new(try!(parser.parse_u8()),
                                     try!(parser.parse_u8()),
                                     try!(parser.parse_u8()),
                                     try!(parser.parse_u8()));
            let proto = try!(parser.parse_u8());
            let len = parser.left();
            let bitmap = try!(parser.parse_octets(len));
            Ok(Some(WKS::new(addr, proto, bitmap)))
        }
    }
}

impl<F: Flavor> fmt::Display for WKS<F> {
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
#[derive(Clone, Debug)]
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
