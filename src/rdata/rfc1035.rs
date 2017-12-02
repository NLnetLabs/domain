//! Record data from [RFC 1035].
//!
//! This RFC defines the initial set of record types.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use std::{fmt, io, ops};
use std::io::Write;
use std::net::Ipv4Addr;
use std::str::FromStr;
use bytes::{BufMut, Bytes, BytesMut};
use ::iana::Rtype;
use ::bits::charstr::CharStr;
use ::bits::compose::{Compose, Compress, Compressor};
use ::bits::name::ParsedDname;
use ::bits::parse::{ParseAll, ParseAllError, ParseOpenError, Parse,
                    Parser, ShortBuf};
use ::bits::rdata::RtypeRecordData;
use ::bits::serial::Serial;
use ::master::print::{Print, Printer};
use ::master::scan::{CharSource, ScanError, Scan, Scanner};


//------------ dname_type! --------------------------------------------------

/// A macro for implementing a record data type with a single domain name.
///
/// Implements some basic methods plus the `RecordData`, `FlatRecordData`,
/// and `Display` traits.
macro_rules! dname_type {
    ($target:ident, $rtype:ident, $field:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $target<N> {
            $field: N
        }

        impl<N> $target<N> {
            pub fn new($field: N) -> Self {
                $target { $field: $field }
            }

            pub fn $field(&self) -> &N {
                &self.$field
            }
        }

        //--- From and FromStr

        impl<N> From<N> for $target<N> {
            fn from(name: N) -> Self {
                Self::new(name)
            }
        }

        impl<N: FromStr> FromStr for $target<N> {
            type Err = N::Err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                N::from_str(s).map(Self::new)
            }
        }

        
        //--- Parse, ParseAll, Compose, and Compress

        impl Parse for $target<ParsedDname> {
            type Err = <ParsedDname as Parse>::Err;

            fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
                ParsedDname::parse(parser).map(Self::new)
            }
        }

        impl ParseAll for $target<ParsedDname> {
            type Err = <ParsedDname as ParseAll>::Err;

            fn parse_all(parser: &mut Parser, len: usize)
                         -> Result<Self, Self::Err> {
                ParsedDname::parse_all(parser, len).map(Self::new)
            }
        }

        impl<N: Compose> Compose for $target<N> {
            fn compose_len(&self) -> usize {
                self.$field.compose_len()
            }
        
            fn compose<B: BufMut>(&self, buf: &mut B) {
                self.$field.compose(buf)
            }
        }

        impl<N: Compress> Compress for $target<N> {
            fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
                self.$field.compress(buf)
            }
        }


        //--- Scan and Print

        impl<N: Scan> Scan for $target<N> {
            fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                                   -> Result<Self, ScanError> {
                N::scan(scanner).map(Self::new)
            }
        }

        impl<N: Print> Print for $target<N> {
            fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                                   -> Result<(), io::Error> {
                self.$field.print(printer)
            }
        }


        //--- RtypeRecordData

        impl<N> RtypeRecordData for $target<N> {
            const RTYPE: Rtype = Rtype::$rtype;
        }


        //--- Deref

        impl<N> ops::Deref for $target<N> {
            type Target = N;

            fn deref(&self) -> &Self::Target {
                &self.$field
            }
        }


        //--- Display

        impl<N: fmt::Display> fmt::Display for $target<N> {
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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
}


//--- From and FromStr

impl From<Ipv4Addr> for A {
    fn from(addr: Ipv4Addr) -> Self {
        Self::new(addr)
    }
}

impl From<A> for Ipv4Addr {
    fn from(a: A) -> Self {
        a.addr
    }
}

impl FromStr for A {
    type Err = <Ipv4Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Addr::from_str(s).map(A::new)
    }
}


//--- Parse, ParseAll, Compose, and Compress

impl Parse for A {
    type Err = <Ipv4Addr as Parse>::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ipv4Addr::parse(parser).map(Self::new)
    }
}

impl ParseAll for A {
    type Err = <Ipv4Addr as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        Ipv4Addr::parse_all(parser, len).map(Self::new)
    }
}

impl Compose for A {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.addr.compose(buf)
    }
}

impl Compress for A {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Print

impl Scan for A {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_string_phrase(|res| A::from_str(&res).map_err(Into::into))
    }
}

impl Print for A {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        write!(printer.item()?, "{}", self.addr)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for A {
    const RTYPE: Rtype = Rtype::A;
}


//--- Deref and DerefMut

impl ops::Deref for A {
    type Target = Ipv4Addr;

    fn deref(&self) -> &Self::Target {
        &self.addr
    }
}

impl ops::DerefMut for A {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.addr
    }
}


//--- AsRef and AsMut

impl AsRef<Ipv4Addr> for A {
    fn as_ref(&self) -> &Ipv4Addr {
        &self.addr
    }
}

impl AsMut<Ipv4Addr> for A {
    fn as_mut(&mut self) -> &mut Ipv4Addr {
        &mut self.addr
    }
}


//--- Display

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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hinfo {
    cpu: CharStr,
    os: CharStr,
}

impl Hinfo {
    /// Creates a new Hinfo record data from the components.
    pub fn new(cpu: CharStr, os: CharStr) -> Self {
        Hinfo{cpu: cpu, os: os}
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &CharStr {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &CharStr {
        &self.os
    }
}

//--- Parse, Compose, and Compress

impl Parse for Hinfo {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(CharStr::parse(parser)?, CharStr::parse(parser)?))
    }
}

impl ParseAll for Hinfo {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize)
                    -> Result<Self, Self::Err> {
        let cpu = CharStr::parse(parser)?;
        let len = match len.checked_sub(cpu.len() + 1) {
            Some(len) => len,
            None => return Err(ParseAllError::ShortField)
        };
        let os = CharStr::parse_all(parser, len)?;
        Ok(Hinfo::new(cpu, os))
    }
}

impl Compose for Hinfo {
    fn compose_len(&self) -> usize {
        self.cpu.compose_len() + self.os.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.cpu.compose(buf);
        self.os.compose(buf);
    }
}

impl Compress for Hinfo {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Print

impl Scan for Hinfo {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(CharStr::scan(scanner)?, CharStr::scan(scanner)?))
    }
}

impl Print for Hinfo {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        self.cpu.print(printer)?;
        self.os.print(printer)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Hinfo {
    const RTYPE: Rtype = Rtype::Hinfo;
}


//--- Display

impl fmt::Display for Hinfo {
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Minfo<N=ParsedDname> {
    rmailbx: N,
    emailbx: N,
}

impl<N> Minfo<N> {
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


//--- Parse, ParseAll, Compose, and Compress

impl<N: Parse> Parse for Minfo<N> {
    type Err = N::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(N::parse(parser)?, N::parse(parser)?))
    }
}

impl<N: Parse + ParseAll> ParseAll for Minfo<N>
     where <N as ParseAll>::Err: From<<N as Parse>::Err> + From<ShortBuf> {
    type Err = <N as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let pos = parser.pos();
        let rmailbx = N::parse(parser)?;
        let rlen = parser.pos() - pos;
        let len = if len <= rlen {
            // Because a domain name can never be empty, we seek back to the
            // beginning and reset the length to zero.
            parser.seek(pos)?;
            0
        }
        else {
            len - rlen
        };
        let emailbx = N::parse_all(parser, len)?;
        Ok(Self::new(rmailbx, emailbx))
    }
}

impl<N: Compose> Compose for Minfo<N> {
    fn compose_len(&self) -> usize {
        self.rmailbx.compose_len() + self.emailbx.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.rmailbx.compose(buf);
        self.emailbx.compose(buf);
    }
}

impl<N: Compress> Compress for Minfo<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        self.rmailbx.compress(buf)?;
        self.emailbx.compress(buf)
    }
}


//--- Scan and Print

impl<N: Scan> Scan for Minfo<N> {
    fn scan<C: CharSource>(scanner: &mut  Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(N::scan(scanner)?, N::scan(scanner)?))
    }
}

impl<N: Print> Print for Minfo<N> {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        self.rmailbx.print(printer)?;
        self.emailbx.print(printer)
    }
}


//--- RecordData

impl<N> RtypeRecordData for Minfo<N> {
    const RTYPE: Rtype = Rtype::Minfo;
}


//--- Display

impl<N: fmt::Display> fmt::Display for Minfo<N> {
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Mx<N=ParsedDname> {
    preference: u16,
    exchange: N,
}

impl<N> Mx<N> {
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


//--- Parse, ParseAll, Compose, Compress

impl<N: Parse> Parse for Mx<N>
     where N::Err: From<ShortBuf> {
    type Err = N::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(u16::parse(parser)?, N::parse(parser)?))
    }
}

impl<N: ParseAll> ParseAll for Mx<N>
     where N::Err: From<ParseOpenError> + From<ShortBuf> {
    type Err = N::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 3 {
            return Err(ParseOpenError::ShortField.into())
        }
        Ok(Self::new(u16::parse(parser)?, N::parse_all(parser, len - 2)?))
    }
}

impl<N: Compose> Compose for Mx<N> {
    fn compose_len(&self) -> usize {
        self.exchange.compose_len() + 2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.preference.compose(buf);
        self.exchange.compose(buf);
    }
}

impl<N: Compress> Compress for Mx<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(&self.preference)?;
        self.exchange.compress(buf)
    }
}


//--- Scan and Print

impl<N: Scan> Scan for Mx<N> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(u16::scan(scanner)?, N::scan(scanner)?))
    }
}

impl<N: Print> Print for Mx<N> {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        self.preference.print(printer)?;
        self.exchange.print(printer)
    }
}


//--- RtypeRecordData

impl<N> RtypeRecordData for Mx<N> {
    const RTYPE: Rtype = Rtype::Mx;
}


//--- Display

impl<N: fmt::Display> fmt::Display for Mx<N> {
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Null {
    data: Bytes,
}

impl Null {
    /// Creates new, empty owned Null record data.
    pub fn new(data: Bytes) -> Self {
        Null { data }
    }

    /// The raw content of the record.
    pub fn data(&self) -> &Bytes {
        &self.data
    }
}


//--- From

impl From<Bytes> for Null {
    fn from(data: Bytes) -> Self {
        Self::new(data)
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Null {
    type Err = ShortBuf;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        parser.parse_bytes(len).map(Self::new)
    }
}

impl Compose for Null {
    fn compose_len(&self) -> usize {
        self.data.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.data.as_ref())
    }
}

impl Compress for Null {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Null {
    const RTYPE: Rtype = Rtype::Null;
}


//--- Deref

impl ops::Deref for Null {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}


//--- AsRef

impl AsRef<Bytes> for Null {
    fn as_ref(&self) -> &Bytes {
        &self.data
    }
}

impl AsRef<[u8]> for Null {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}


//--- Display

impl fmt::Display for Null {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data().len())?;
        for ch in self.data().iter() {
            write!(f, " {:02x}", ch)?;
        }
        Ok(())
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
/// Soa records mark the top of a zone and contain information pertinent to
/// name server maintenance operations.
///
/// The Soa record type is defined in RFC 1035, section 3.3.13.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub struct Soa<N=ParsedDname> {
    mname: N,
    rname: N,
    serial: Serial,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum:u32 
}

impl<N> Soa<N> {
    /// Creates new Soa record data from content.
    pub fn new(mname: N, rname: N, serial: Serial,
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
    pub fn serial(&self) -> Serial {
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


//--- Parse, ParseAll, Compose, and Compress

impl<N: Parse> Parse for Soa<N> where N::Err: From<ShortBuf> {
    type Err = N::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(N::parse(parser)?, N::parse(parser)?,
                     Serial::parse(parser)?, u32::parse(parser)?,
                     u32::parse(parser)?, u32::parse(parser)?,
                     u32::parse(parser)?))
    }
}

impl<N: ParseAll + Parse> ParseAll for Soa<N>
        where <N as ParseAll>::Err: From<<N as Parse>::Err>,
              <N as ParseAll>::Err: From<ParseAllError>,
              <N as Parse>::Err: From<ShortBuf> {
    type Err = <N as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let tmp = parser.clone();
        let res = <Self as Parse>::parse(parser)?;
        if tmp.pos() - parser.pos() < len {
            Err(ParseAllError::TrailingData.into())
        }
        else if tmp.pos() - parser.pos() > len {
            Err(ParseAllError::ShortField.into())
        }
        else {
            Ok(res)
        }
    }
}

impl<N: Compose> Compose for Soa<N> {
    fn compose_len(&self) -> usize {
        self.mname.compose_len() + self.rname.compose_len() + (5 * 4)
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.mname.compose(buf);
        self.rname.compose(buf);
        self.serial.compose(buf);
        self.refresh.compose(buf);
        self.retry.compose(buf);
        self.expire.compose(buf);
        self.minimum.compose(buf);
    }
}

impl<N: Compress> Compress for Soa<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        self.mname.compress(buf)?;
        self.rname.compress(buf)?;
        buf.compose(&self.serial)?;
        buf.compose(&self.refresh)?;
        buf.compose(&self.retry)?;
        buf.compose(&self.expire)?;
        buf.compose(&self.minimum)
    }
}


//--- Scan and Print

impl<N: Scan> Scan for Soa<N> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(N::scan(scanner)?, N::scan(scanner)?,
                     Serial::scan(scanner)?, u32::scan(scanner)?,
                     u32::scan(scanner)?, u32::scan(scanner)?,
                     u32::scan(scanner)?))
    }
}

impl<N: Print> Print for Soa<N> {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        self.mname.print(printer)?;
        self.rname.print(printer)?;
        self.serial.print(printer)?;
        self.refresh.print(printer)?;
        self.retry.print(printer)?;
        self.expire.print(printer)?;
        self.minimum.print(printer)
    }
}


//--- RecordData

impl<N> RtypeRecordData for Soa<N> {
    const RTYPE: Rtype = Rtype::Soa;
}


//--- Display

impl<N: fmt::Display> fmt::Display for Soa<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {}", self.mname, self.rname, self.serial,
               self.refresh, self.retry, self.expire, self.minimum)
    }
}


//------------ Txt ----------------------------------------------------------

/// Txt record data.
///
/// Txt records hold descriptive text.
///
/// The Txt record type is defined in RFC 1035, section 3.3.14.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Txt {
    text: Bytes,
}

impl Txt {
    /// Creates a new Txt record from a single character string.
    pub fn new(text: CharStr) -> Self {
        Txt { text: text.into_bytes() }
    }

    /// Returns an iterator over the text items.
    ///
    /// The Txt format contains one or more length-delimited byte strings.
    /// This method returns an iterator over each of them.
    pub fn iter(&self) -> TxtIter {
        TxtIter::new(self.text.clone())
    }

    /// Returns the text content.
    ///
    /// If the data is only one single character string, returns a simple
    /// clone of the slice with the data. If there are several character
    /// strings, their content will be copied together into one single,
    /// newly allocated bytes value.
    ///
    /// Access to the individual character strings is possible via iteration.
    pub fn text(&self) -> Bytes {
        if self.text[0] as usize == self.text.len() + 1 {
            self.text.slice_from(1)
        }
        else {
            // Capacity will be a few bytes too much. Probably better than
            // re-allocating.
            let mut res = BytesMut::with_capacity(self.text.len());
            for item in self.iter() {
                res.put_slice(item.as_ref());
            }
            res.freeze()
        }
    }
}


//--- IntoIterator

impl IntoIterator for Txt {
    type Item = CharStr;
    type IntoIter = TxtIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a Txt {
    type Item = CharStr;
    type IntoIter = TxtIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Txt {
    type Err = ParseOpenError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let text = parser.parse_bytes(len)?;
        let mut tmp = Parser::from_bytes(text.clone());
        while tmp.remaining() > 0 {
            CharStr::skip(&mut tmp).map_err(|_| ParseOpenError::ShortField)?
        }
        Ok(Txt { text })
    }
}

impl Compose for Txt {
    fn compose_len(&self) -> usize {
        self.text.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.text.as_ref())
    }
}

impl Compress for Txt {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Print

impl Scan for Txt {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        let first = CharStr::scan(scanner)?;
        let second = match CharStr::scan(scanner) {
            Err(_) => return Ok(Txt::new(first)),
            Ok(second) => second,
        };
        let mut text = first.into_bytes();
        text.extend_from_slice(second.as_ref());
        while let Ok(some) = CharStr::scan(scanner) {
            text.extend_from_slice(some.as_ref());
        }
        Ok(Txt { text })
    }
}

impl Print for Txt {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        for item in self.iter() {
            item.print(printer)?
        }
        Ok(())
    }
}


//--- RecordData

impl RtypeRecordData for Txt {
    const RTYPE: Rtype = Rtype::Txt;
}


//--- Display

impl fmt::Display for Txt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut items = self.iter();
        match items.next() {
            Some(item) => item.fmt(f)?,
            None => return Ok(())
        }
        for item in items {
            write!(f, " {}", item)?;
        }
        Ok(())
    }
}


//------------ TxtIter -------------------------------------------------------

/// An iterator over the character strings of a Txt record.
#[derive(Clone, Debug)]
pub struct TxtIter {
    parser: Parser,
}

impl TxtIter {
    fn new(text: Bytes)-> Self {
        TxtIter { parser: Parser::from_bytes(text) }
    }
}

impl Iterator for TxtIter {
    type Item = CharStr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            None
        }
        else {
            Some(CharStr::parse(&mut self.parser).unwrap())
        }
    }
}


//------------ Wks ----------------------------------------------------------

/// Wks record data.
///
/// Wks records describe the well-known services supported by a particular
/// protocol on a particular internet address.
///
/// The Wks record type is defined in RFC 1035, section 3.4.2.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Wks {
    address: Ipv4Addr,
    protocol: u8,
    bitmap: Bytes,
}


impl Wks {
    /// Creates a new record data from components.
    pub fn new(address: Ipv4Addr, protocol: u8, bitmap: Bytes) -> Self {
        Wks { address, protocol, bitmap }
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
    pub fn bitmap(&self) -> &Bytes {
        &self.bitmap
    }

    /// Returns whether a certain service is being provided.
    pub fn serves(&self, port: u16) -> bool {
        let octet = (port / 8) as usize;
        let bit = (port % 8) as usize;
        match self.bitmap.get(octet) {
            Some(x) => (x >> bit) > 0,
            None => false
        }
    }

    /// Returns an iterator over the served ports.
    pub fn iter(&self) -> WksIter {
        WksIter::new(self.bitmap.clone())
    }
}


//--- ParseAll, Compose, Compress

impl ParseAll for Wks {
    type Err = ParseOpenError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 5 {
            return Err(ParseOpenError::ShortField)
        }
        Ok(Self::new(Ipv4Addr::parse(parser)?, u8::parse(parser)?,
                     parser.parse_bytes(len - 5)?))
    }
}

impl Compose for Wks {
    fn compose_len(&self) -> usize {
        self.bitmap.len() + 5
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.address.compose(buf);
        self.protocol.compose(buf);
        self.bitmap.compose(buf);
    }
}

impl Compress for Wks {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Print

impl Scan for Wks {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        let address = scanner.scan_string_phrase(|res| {
            Ipv4Addr::from_str(&res).map_err(Into::into)
        })?;
        let protocol = u8::scan(scanner)?;
        let mut builder = WksBuilder::new(address, protocol);
        while let Ok(service) = u16::scan(scanner) {
            builder.add_service(service)
        }
        Ok(builder.finish())
    }
}

impl Print for Wks {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        self.address.print(printer)?;
        self.protocol.print(printer)?;
        for service in self.iter() {
            service.print(printer)?;
        }
        Ok(())
    }
}


//--- RecordData

impl RtypeRecordData for Wks {
    const RTYPE: Rtype = Rtype::Wks;
}


//--- Display

impl fmt::Display for Wks {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.address, self.protocol)?;
        for service in self.iter() {
            write!(f, " {}", service)?;
        }
        Ok(())
    }
}


//------------ WksIter -------------------------------------------------------

/// An iterator over the services active in a Wks record.
///
/// This iterates over the port numbers in growing order.
#[derive(Clone, Debug)]
pub struct WksIter {
    bitmap: Bytes,
    octet: usize,
    bit: usize
}

impl WksIter {
    fn new(bitmap: Bytes) -> Self {
        WksIter { bitmap, octet: 0, bit: 0 }
    }

    fn serves(&self) -> bool {
        (self.bitmap[self.octet] >> self.bit) > 0
    }
}

impl Iterator for WksIter {
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


//------------ WksBuilder ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct WksBuilder {
    address: Ipv4Addr,
    protocol: u8,
    bitmap: BytesMut,
}

impl WksBuilder {
    pub fn new(address: Ipv4Addr, protocol: u8) -> Self {
        WksBuilder { address, protocol, bitmap: BytesMut::new() }
    }

    pub fn add_service(&mut self, service: u16) {
        let octet = (service >> 2) as usize;
        let bit = 1 << (service & 0x3);
        while self.bitmap.len() < octet + 1 {
            self.bitmap.extend_from_slice(b"0")
        }
        self.bitmap[octet] |= bit;
    }

    pub fn finish(self) -> Wks {
        Wks::new(self.address, self.protocol, self.bitmap.freeze())
    }
}


