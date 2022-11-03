//! Record data from [RFC 1035]: initial record types.
//!
//! This RFC defines the initial set of record types.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use crate::base::charstr::{CharStr, CharStrError};
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{Dname, ParsedDname, PushError, ToDname};
use crate::base::net::Ipv4Addr;
use crate::base::octets::{
    Compose, EmptyBuilder, FromBuilder, OctetsBuilder, OctetsFrom,
    OctetsInto, OctetsRef, Parse, ParseError, Parser, ShortBuf,
};
#[cfg(feature = "serde")]
use crate::base::octets::{DeserializeOctets, SerializeOctets};
use crate::base::rdata::RtypeRecordData;
use crate::base::scan::{Scan, Scanner, ScannerError, Symbol};
use crate::base::serial::Serial;
#[cfg(feature = "bytes")]
use bytes::BytesMut;
use core::cmp::Ordering;
use core::str::FromStr;
use core::{fmt, hash, ops, str};

//------------ A ------------------------------------------------------------

/// A record data.
///
/// A records convey the IPv4 address of a host. The wire format is the 32
/// bit IPv4 address in network byte order. The representation file format
/// is the usual dotted notation.
///
/// The A record type is defined in RFC 1035, section 3.4.1.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct A {
    addr: Ipv4Addr,
}

impl A {
    /// Creates a new A record data from an IPv4 address.
    pub fn new(addr: Ipv4Addr) -> A {
        A { addr }
    }

    /// Creates a new A record from the IPv4 address components.
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8) -> A {
        A::new(Ipv4Addr::new(a, b, c, d))
    }

    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }
    pub fn set_addr(&mut self, addr: Ipv4Addr) {
        self.addr = addr
    }

    pub fn flatten_into(self) -> Result<A, PushError> {
        Ok(self)
    }
}

//--- OctetsFrom

impl OctetsFrom<A> for A {
    fn octets_from(source: A) -> Result<Self, ShortBuf> {
        Ok(source)
    }
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

//--- CanonicalOrd

impl CanonicalOrd for A {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

//--- Parse and Compose

impl<Octets: AsRef<[u8]>> Parse<Octets> for A {
    fn parse(parser: &mut Parser<Octets>) -> Result<Self, ParseError> {
        Ipv4Addr::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser<Octets>) -> Result<(), ParseError> {
        Ipv4Addr::skip(parser)
    }
}

impl Compose for A {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        self.addr.compose(target)
    }
}

//--- Scan and Display

impl<S: Scanner> Scan<S> for A {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        let token = scanner.scan_octets()?;
        let token = str::from_utf8(token.as_ref())
            .map_err(|_| S::Error::custom("expected IPv4 address"))?;
        A::from_str(token)
            .map_err(|_| S::Error::custom("expected IPv4 address"))
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
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

//------------ Cname --------------------------------------------------------

dname_type! {
    /// CNAME record data.
    ///
    /// The CNAME record specifies the canonical or primary name for domain
    /// name alias.
    ///
    /// The CNAME type is defined in RFC 1035, section 3.3.1.
    (Cname, Cname, cname)
}

//------------ Hinfo --------------------------------------------------------

/// Hinfo record data.
///
/// Hinfo records are used to acquire general information about a host,
/// specifically the CPU type and operating system type.
///
/// The Hinfo type is defined in RFC 1035, section 3.3.2.
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "Octets: AsRef<[u8]> + crate::base::octets::SerializeOctets",
        deserialize = "Octets: \
                crate::base::octets::FromBuilder \
                + crate::base::octets::DeserializeOctets<'de>, \
            <Octets as FromBuilder>::Builder: EmptyBuilder ",
    ))
)]
pub struct Hinfo<Octets> {
    cpu: CharStr<Octets>,
    os: CharStr<Octets>,
}

impl<Octets> Hinfo<Octets> {
    /// Creates a new Hinfo record data from the components.
    pub fn new(cpu: CharStr<Octets>, os: CharStr<Octets>) -> Self {
        Hinfo { cpu, os }
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &CharStr<Octets> {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &CharStr<Octets> {
        &self.os
    }
}

impl<SrcOctets> Hinfo<SrcOctets> {
    pub fn flatten_into<Octets>(self) -> Result<Hinfo<Octets>, PushError>
    where
        Octets: OctetsFrom<SrcOctets>,
    {
        let Self { cpu, os } = self;
        Ok(Hinfo::new(cpu.octets_into()?, os.octets_into()?))
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<Hinfo<SrcOctets>> for Hinfo<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Hinfo<SrcOctets>) -> Result<Self, ShortBuf> {
        Ok(Hinfo::new(
            CharStr::octets_from(source.cpu)?,
            CharStr::octets_from(source.os)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Hinfo<Other>> for Hinfo<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Hinfo<Other>) -> bool {
        self.cpu.eq(&other.cpu) && self.os.eq(&other.os)
    }
}

impl<Octets: AsRef<[u8]>> Eq for Hinfo<Octets> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Hinfo<Other>> for Hinfo<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Hinfo<Other>) -> Option<Ordering> {
        match self.cpu.partial_cmp(&other.cpu) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.os.partial_cmp(&other.os)
    }
}

impl<Octets, Other> CanonicalOrd<Hinfo<Other>> for Hinfo<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Hinfo<Other>) -> Ordering {
        match self.cpu.canonical_cmp(&other.cpu) {
            Ordering::Equal => {}
            other => return other,
        }
        self.os.canonical_cmp(&other.os)
    }
}

impl<Octets: AsRef<[u8]>> Ord for Hinfo<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.cpu.cmp(&other.cpu) {
            Ordering::Equal => {}
            other => return other,
        }
        self.os.cmp(&other.os)
    }
}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Hinfo<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.cpu.hash(state);
        self.os.hash(state);
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Hinfo<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Ok(Self::new(CharStr::parse(parser)?, CharStr::parse(parser)?))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        CharStr::skip(parser)?;
        CharStr::skip(parser)?;
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Hinfo<Octets> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.cpu.compose(target)?;
            self.os.compose(target)
        })
    }
}

//--- Scan and Display

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for Hinfo<Octets> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(scanner.scan_charstr()?, scanner.scan_charstr()?))
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Hinfo<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}

//--- Debug

impl<Octets: AsRef<[u8]>> fmt::Debug for Hinfo<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Hinfo")
            .field("cpu", &self.cpu)
            .field("os", &self.os)
            .finish()
    }
}

//--- RtypeRecordData

impl<Octets> RtypeRecordData for Hinfo<Octets> {
    const RTYPE: Rtype = Rtype::Hinfo;
}

//------------ Mb -----------------------------------------------------------

dname_type! {
    /// MB record data.
    ///
    /// The experimental MB record specifies a host that serves a mailbox.
    ///
    /// The MB record type is defined in RFC 1035, section 3.3.3.
    (Mb, Mb, madname)
}

//------------ Md -----------------------------------------------------------

dname_type! {
    /// MD record data.
    ///
    /// The MD record specifices a host which has a mail agent for
    /// the domain which should be able to deliver mail for the domain.
    ///
    /// The MD record is obsolete. It is recommended to either reject the record
    /// or convert them into an Mx record at preference 0.
    ///
    /// The MD record type is defined in RFC 1035, section 3.3.4.
    (Md, Md, madname)
}

//------------ Mf -----------------------------------------------------------

dname_type! {
    /// MF record data.
    ///
    /// The MF record specifices a host which has a mail agent for
    /// the domain which will be accept mail for forwarding to the domain.
    ///
    /// The MF record is obsolete. It is recommended to either reject the record
    /// or convert them into an Mx record at preference 10.
    ///
    /// The MF record type is defined in RFC 1035, section 3.3.5.
    (Mf, Mf, madname)
}

//------------ Mg -----------------------------------------------------------

dname_type! {
    /// MG record data.
    ///
    /// The MG record specifices a mailbox which is a member of the mail group
    /// specified by the domain name.
    ///
    /// The MG record is experimental.
    ///
    /// The MG record type is defined in RFC 1035, section 3.3.6.
    (Mg, Mg, madname)
}

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
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Minfo<N> {
    rmailbx: N,
    emailbx: N,
}

impl<N> Minfo<N> {
    /// Creates a new Minfo record data from the components.
    pub fn new(rmailbx: N, emailbx: N) -> Self {
        Minfo { rmailbx, emailbx }
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

impl<Ref> Minfo<ParsedDname<Ref>>
where
    Ref: OctetsRef,
{
    pub fn flatten_into<Octets>(
        self,
    ) -> Result<Minfo<Dname<Octets>>, PushError>
    where
        Octets: OctetsFrom<Ref::Range> + FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let Self { rmailbx, emailbx } = self;
        Ok(Minfo::new(rmailbx.flatten_into()?, emailbx.flatten_into()?))
    }
}

//--- OctetsFrom

impl<Name, SrcName> OctetsFrom<Minfo<SrcName>> for Minfo<Name>
where
    Name: OctetsFrom<SrcName>,
{
    fn octets_from(source: Minfo<SrcName>) -> Result<Self, ShortBuf> {
        Ok(Minfo::new(
            Name::octets_from(source.rmailbx)?,
            Name::octets_from(source.emailbx)?,
        ))
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Minfo<NN>> for Minfo<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &Minfo<NN>) -> bool {
        self.rmailbx.name_eq(&other.rmailbx)
            && self.emailbx.name_eq(&other.emailbx)
    }
}

impl<N: ToDname> Eq for Minfo<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Minfo<NN>> for Minfo<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn partial_cmp(&self, other: &Minfo<NN>) -> Option<Ordering> {
        match self.rmailbx.name_cmp(&other.rmailbx) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        Some(self.emailbx.name_cmp(&other.emailbx))
    }
}

impl<N: ToDname> Ord for Minfo<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.rmailbx.name_cmp(&other.rmailbx) {
            Ordering::Equal => {}
            other => return other,
        }
        self.emailbx.name_cmp(&other.emailbx)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Minfo<NN>> for Minfo<N> {
    fn canonical_cmp(&self, other: &Minfo<NN>) -> Ordering {
        match self.rmailbx.lowercase_composed_cmp(&other.rmailbx) {
            Ordering::Equal => {}
            other => return other,
        }
        self.emailbx.lowercase_composed_cmp(&other.emailbx)
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Minfo<ParsedDname<Ref>> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Ok(Self::new(
            ParsedDname::parse(parser)?,
            ParsedDname::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        ParsedDname::skip(parser)?;
        ParsedDname::skip(parser)?;
        Ok(())
    }
}

impl<N: ToDname> Compose for Minfo<N> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            target.append_compressed_dname(&self.rmailbx)?;
            target.append_compressed_dname(&self.emailbx)
        })
    }

    fn compose_canonical<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.rmailbx.compose_canonical(target)?;
            self.emailbx.compose_canonical(target)
        })
    }
}

//--- Scan and Display

impl<N, S: Scanner<Dname = N>> Scan<S> for Minfo<N> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(scanner.scan_dname()?, scanner.scan_dname()?))
    }
}

impl<N: fmt::Display> fmt::Display for Minfo<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {}.", self.rmailbx, self.emailbx)
    }
}

//--- RecordData

impl<N> RtypeRecordData for Minfo<N> {
    const RTYPE: Rtype = Rtype::Minfo;
}

//------------ Mr -----------------------------------------------------------

dname_type! {
    /// MR record data.
    ///
    /// The MR record specifices a mailbox which is the proper rename of the
    /// specified mailbox.
    ///
    /// The MR record is experimental.
    ///
    /// The MR record type is defined in RFC 1035, section 3.3.8.
    (Mr, Mr, newname)
}

//------------ Mx -----------------------------------------------------------

/// Mx record data.
///
/// The Mx record specifies a host willing to serve as a mail exchange for
/// the owner name.
///
/// The Mx record type is defined in RFC 1035, section 3.3.9.
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mx<N> {
    preference: u16,
    exchange: N,
}

impl<N> Mx<N> {
    /// Creates a new Mx record data from the components.
    pub fn new(preference: u16, exchange: N) -> Self {
        Mx {
            preference,
            exchange,
        }
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

impl<Ref> Mx<ParsedDname<Ref>>
where
    Ref: OctetsRef,
{
    pub fn flatten_into<Octets>(self) -> Result<Mx<Dname<Octets>>, PushError>
    where
        Octets: OctetsFrom<<Ref as OctetsRef>::Range> + FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let Self {
            preference,
            exchange,
        } = self;
        Ok(Mx::new(preference, exchange.flatten_into()?))
    }
}

//--- OctetsFrom

impl<Name, SrcName> OctetsFrom<Mx<SrcName>> for Mx<Name>
where
    Name: OctetsFrom<SrcName>,
{
    fn octets_from(source: Mx<SrcName>) -> Result<Self, ShortBuf> {
        Ok(Mx::new(
            source.preference,
            Name::octets_from(source.exchange)?,
        ))
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Mx<NN>> for Mx<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &Mx<NN>) -> bool {
        self.preference == other.preference
            && self.exchange.name_eq(&other.exchange)
    }
}

impl<N: ToDname> Eq for Mx<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Mx<NN>> for Mx<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn partial_cmp(&self, other: &Mx<NN>) -> Option<Ordering> {
        match self.preference.partial_cmp(&other.preference) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        Some(self.exchange.name_cmp(&other.exchange))
    }
}

impl<N: ToDname> Ord for Mx<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.preference.cmp(&other.preference) {
            Ordering::Equal => {}
            other => return other,
        }
        self.exchange.name_cmp(&other.exchange)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Mx<NN>> for Mx<N> {
    fn canonical_cmp(&self, other: &Mx<NN>) -> Ordering {
        match self.preference.cmp(&other.preference) {
            Ordering::Equal => {}
            other => return other,
        }
        self.exchange.lowercase_composed_cmp(&other.exchange)
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Mx<ParsedDname<Ref>> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Ok(Self::new(u16::parse(parser)?, ParsedDname::parse(parser)?))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        u16::skip(parser)?;
        ParsedDname::skip(parser)
    }
}

impl<N: ToDname> Compose for Mx<N> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.preference.compose(target)?;
            target.append_compressed_dname(&self.exchange)
        })
    }

    fn compose_canonical<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.preference.compose(target)?;
            self.exchange.compose_canonical(target)
        })
    }
}

//--- Scan and Display

impl<N, S: Scanner<Dname = N>> Scan<S> for Mx<N> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(u16::scan(scanner)?, scanner.scan_dname()?))
    }
}

impl<N: fmt::Display> fmt::Display for Mx<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}.", self.preference, self.exchange)
    }
}

//--- RtypeRecordData

impl<N> RtypeRecordData for Mx<N> {
    const RTYPE: Rtype = Rtype::Mx;
}

//------------ Ns -----------------------------------------------------------

dname_type! {
    /// NS record data.
    ///
    /// NS records specify hosts that are authoritative for a class and domain.
    ///
    /// The NS record type is defined in RFC 1035, section 3.3.11.
    (Ns, Ns, nsdname)
}

//------------ Null ---------------------------------------------------------

/// Null record data.
///
/// Null records can contain whatever data. They are experimental and not
/// allowed in zone files.
///
/// The Null record type is defined in RFC 1035, section 3.3.10.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Null<Octets> {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::base::octets::SerializeOctets::serialize_octets",
            deserialize_with = "crate::base::octets::DeserializeOctets::deserialize_octets",
            bound(
                serialize = "Octets: crate::base::octets::SerializeOctets",
                deserialize = "Octets: crate::base::octets::DeserializeOctets<'de>",
            )
        )
    )]
    data: Octets,
}

impl<Octets> Null<Octets> {
    /// Creates new, empty owned Null record data.
    pub fn new(data: Octets) -> Self {
        Null { data }
    }

    /// The raw content of the record.
    pub fn data(&self) -> &Octets {
        &self.data
    }
}

impl<Octets: AsRef<[u8]>> Null<Octets> {
    pub fn len(&self) -> usize {
        self.data.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.as_ref().is_empty()
    }
}

impl<SrcOctets> Null<SrcOctets> {
    pub fn flatten_into<Octets>(self) -> Result<Null<Octets>, PushError>
    where
        Octets: OctetsFrom<SrcOctets>,
    {
        Ok(Null::new(self.data.octets_into()?))
    }
}

//--- From

impl<Octets> From<Octets> for Null<Octets> {
    fn from(data: Octets) -> Self {
        Self::new(data)
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<Null<SrcOctets>> for Null<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Null<SrcOctets>) -> Result<Self, ShortBuf> {
        Octets::octets_from(source.data).map(Self::new)
    }
}

//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Null<Other>> for Null<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Null<Other>) -> bool {
        self.data.as_ref().eq(other.data.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Eq for Null<Octets> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Null<Other>> for Null<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Null<Other>) -> Option<Ordering> {
        self.data.as_ref().partial_cmp(other.data.as_ref())
    }
}

impl<Octets, Other> CanonicalOrd<Null<Other>> for Null<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Null<Other>) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Ord for Null<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Null<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.data.as_ref().hash(state)
    }
}

//--- ParseAll and Compose

impl<Ref: OctetsRef> Parse<Ref> for Null<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.remaining();
        parser.parse_octets(len).map(Self::new)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Null<Octets> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(self.data.as_ref())
    }
}

//--- RtypeRecordData

impl<Octets> RtypeRecordData for Null<Octets> {
    const RTYPE: Rtype = Rtype::Null;
}

//--- Deref

impl<Octets> ops::Deref for Null<Octets> {
    type Target = Octets;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

//--- AsRef

impl<Octets: AsRef<Other>, Other> AsRef<Other> for Null<Octets> {
    fn as_ref(&self) -> &Other {
        self.data.as_ref()
    }
}

//--- Display and Debug

impl<Octets: AsRef<[u8]>> fmt::Display for Null<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data.as_ref().len())?;
        for ch in self.data.as_ref().iter() {
            write!(f, " {:02x}", ch)?;
        }
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> fmt::Debug for Null<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Null(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

//------------ Ptr ----------------------------------------------------------

dname_type! {
    /// PTR record data.
    ///
    /// PRT records are used in special domains to point to some other location
    /// in the domain space.
    ///
    /// The PTR record type is defined in RFC 1035, section 3.3.12.
    (Ptr, Ptr, ptrdname)
}

impl<N> Ptr<N> {
    pub fn into_ptrdname(self) -> N {
        self.ptrdname
    }
}

//------------ Soa ----------------------------------------------------------

/// Soa record data.
///
/// Soa records mark the top of a zone and contain information pertinent to
/// name server maintenance operations.
///
/// The Soa record type is defined in RFC 1035, section 3.3.13.
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Soa<N> {
    mname: N,
    rname: N,
    serial: Serial,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl<N> Soa<N> {
    /// Creates new Soa record data from content.
    pub fn new(
        mname: N,
        rname: N,
        serial: Serial,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
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

impl<Ref> Soa<ParsedDname<Ref>>
where
    Ref: OctetsRef,
{
    pub fn flatten_into<Octets>(self) -> Result<Soa<Dname<Octets>>, PushError>
    where
        Octets: OctetsFrom<Ref::Range> + FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } = self;

        Ok(Soa::new(
            mname.flatten_into()?,
            rname.flatten_into()?,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        ))
    }
}

//--- OctetsFrom

impl<Name, SrcName> OctetsFrom<Soa<SrcName>> for Soa<Name>
where
    Name: OctetsFrom<SrcName>,
{
    fn octets_from(source: Soa<SrcName>) -> Result<Self, ShortBuf> {
        Ok(Soa::new(
            Name::octets_from(source.mname)?,
            Name::octets_from(source.rname)?,
            source.serial,
            source.refresh,
            source.retry,
            source.expire,
            source.minimum,
        ))
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Soa<NN>> for Soa<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &Soa<NN>) -> bool {
        self.mname.name_eq(&other.mname)
            && self.rname.name_eq(&other.rname)
            && self.serial == other.serial
            && self.refresh == other.refresh
            && self.retry == other.retry
            && self.expire == other.expire
            && self.minimum == other.minimum
    }
}

impl<N: ToDname> Eq for Soa<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Soa<NN>> for Soa<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn partial_cmp(&self, other: &Soa<NN>) -> Option<Ordering> {
        match self.mname.name_cmp(&other.mname) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        match self.rname.name_cmp(&other.rname) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        match u32::from(self.serial).partial_cmp(&u32::from(other.serial)) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.refresh.partial_cmp(&other.refresh) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.retry.partial_cmp(&other.retry) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.expire.partial_cmp(&other.expire) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.minimum.partial_cmp(&other.minimum)
    }
}

impl<N: ToDname> Ord for Soa<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.mname.name_cmp(&other.mname) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.rname.name_cmp(&other.rname) {
            Ordering::Equal => {}
            other => return other,
        }
        match u32::from(self.serial).cmp(&u32::from(other.serial)) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.refresh.cmp(&other.refresh) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.retry.cmp(&other.retry) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.expire.cmp(&other.expire) {
            Ordering::Equal => {}
            other => return other,
        }
        self.minimum.cmp(&other.minimum)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Soa<NN>> for Soa<N> {
    fn canonical_cmp(&self, other: &Soa<NN>) -> Ordering {
        match self.mname.lowercase_composed_cmp(&other.mname) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.rname.lowercase_composed_cmp(&other.rname) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.serial.canonical_cmp(&other.serial) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.refresh.cmp(&other.refresh) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.retry.cmp(&other.retry) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.expire.cmp(&other.expire) {
            Ordering::Equal => {}
            other => return other,
        }
        self.minimum.cmp(&other.minimum)
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Soa<ParsedDname<Ref>> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Ok(Self::new(
            ParsedDname::parse(parser)?,
            ParsedDname::parse(parser)?,
            Serial::parse(parser)?,
            u32::parse(parser)?,
            u32::parse(parser)?,
            u32::parse(parser)?,
            u32::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        ParsedDname::skip(parser)?;
        ParsedDname::skip(parser)?;
        Serial::skip(parser)?;
        u32::skip(parser)?;
        u32::skip(parser)?;
        u32::skip(parser)?;
        u32::skip(parser)?;
        Ok(())
    }
}

impl<N: ToDname> Compose for Soa<N> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            buf.append_compressed_dname(&self.mname)?;
            buf.append_compressed_dname(&self.rname)?;
            self.serial.compose(buf)?;
            self.refresh.compose(buf)?;
            self.retry.compose(buf)?;
            self.expire.compose(buf)?;
            self.minimum.compose(buf)
        })
    }

    fn compose_canonical<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.mname.compose_canonical(buf)?;
            self.rname.compose_canonical(buf)?;
            self.serial.compose(buf)?;
            self.refresh.compose(buf)?;
            self.retry.compose(buf)?;
            self.expire.compose(buf)?;
            self.minimum.compose(buf)
        })
    }
}

//--- Scan and Display

impl<N, S: Scanner<Dname = N>> Scan<S> for Soa<N> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(
            scanner.scan_dname()?,
            scanner.scan_dname()?,
            Serial::scan(scanner)?,
            u32::scan(scanner)?,
            u32::scan(scanner)?,
            u32::scan(scanner)?,
            u32::scan(scanner)?,
        ))
    }
}

impl<N: fmt::Display> fmt::Display for Soa<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}. {}. {} {} {} {} {}",
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum
        )
    }
}

//--- RecordData

impl<N> RtypeRecordData for Soa<N> {
    const RTYPE: Rtype = Rtype::Soa;
}

//------------ Txt ----------------------------------------------------------

/// Txt record data.
///
/// Txt records hold descriptive text.
///
/// The Txt record type is defined in RFC 1035, section 3.3.14.
#[derive(Clone)]
pub struct Txt<Octets>(Octets);

impl<Octets: FromBuilder> Txt<Octets> {
    /// Creates a new Txt record from a single character string.
    pub fn from_slice(text: &[u8]) -> Result<Self, ShortBuf>
    where
        <Octets as FromBuilder>::Builder: EmptyBuilder + AsMut<[u8]>,
    {
        let mut builder = TxtBuilder::<Octets::Builder>::new();
        builder.append_slice(text)?;
        Ok(builder.finish())
    }
}

impl<Octets: AsRef<[u8]>> Txt<Octets> {
    /// Creates a new TXT record from its encoded content.
    pub fn from_octets(octets: Octets) -> Result<Self, CharStrError> {
        let mut tmp = octets.as_ref();
        while !tmp.is_empty() {
            if tmp.len() <= tmp[0] as usize {
                return Err(CharStrError);
            }
            tmp = &tmp[(tmp[0] as usize) + 1..];
        }
        Ok(Txt(octets))
    }

    /// Returns an iterator over the text items.
    ///
    /// The Txt format contains one or more length-delimited byte strings.
    /// This method returns an iterator over each of them.
    pub fn iter(&self) -> TxtIter {
        TxtIter(self.iter_char_strs())
    }

    pub fn iter_char_strs(&self) -> TxtCharStrIter {
        TxtCharStrIter(Parser::from_ref(self.0.as_ref()))
    }

    pub fn as_flat_slice(&self) -> Option<&[u8]> {
        if self.0.as_ref()[0] as usize == self.0.as_ref().len() - 1 {
            Some(&self.0.as_ref()[1..])
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }

    /// Returns the text content.
    ///
    /// If the data is only one single character string, returns a simple
    /// clone of the slice with the data. If there are several character
    /// strings, their content will be copied together into one single,
    /// newly allocated bytes value.
    ///
    /// Access to the individual character strings is possible via iteration.
    pub fn text<T: FromBuilder>(&self) -> Result<T, ShortBuf>
    where
        <T as FromBuilder>::Builder: EmptyBuilder,
    {
        // Capacity will be a few bytes too much. Probably better than
        // re-allocating.
        let mut res = T::Builder::with_capacity(self.len());
        for item in self.iter() {
            res.append_slice(item)?;
        }
        Ok(res.freeze())
    }
}

impl<SrcOctets> Txt<SrcOctets> {
    pub fn flatten_into<Octets>(self) -> Result<Txt<Octets>, PushError>
    where
        Octets: OctetsFrom<SrcOctets>,
    {
        Ok(Txt(self.0.octets_into()?))
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<Txt<SrcOctets>> for Txt<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Txt<SrcOctets>) -> Result<Self, ShortBuf> {
        Octets::octets_from(source.0).map(Self)
    }
}

//--- IntoIterator

impl<'a, Octets: AsRef<[u8]>> IntoIterator for &'a Txt<Octets> {
    type Item = &'a [u8];
    type IntoIter = TxtIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Txt<Other>> for Txt<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Txt<Other>) -> bool {
        self.iter()
            .flat_map(|s| s.iter().copied())
            .eq(other.iter().flat_map(|s| s.iter().copied()))
    }
}

impl<Octets: AsRef<[u8]>> Eq for Txt<Octets> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Txt<Other>> for Txt<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Txt<Other>) -> Option<Ordering> {
        self.iter()
            .flat_map(|s| s.iter().copied())
            .partial_cmp(other.iter().flat_map(|s| s.iter().copied()))
    }
}

impl<Octets, Other> CanonicalOrd<Txt<Other>> for Txt<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Txt<Other>) -> Ordering {
        // Canonical comparison requires TXT RDATA to be canonically
        // sorted in the wire format.
        // The TXT has each label prefixed by length, which must be
        // taken into account.
        for (a, b) in self.iter().zip(other.iter()) {
            match (a.len(), a).cmp(&(b.len(), b)) {
                Ordering::Equal => continue,
                r => return r,
            }
        }

        Ordering::Equal
    }
}

impl<Octets: AsRef<[u8]>> Ord for Txt<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter()
            .flat_map(|s| s.iter().copied())
            .cmp(other.iter().flat_map(|s| s.iter().copied()))
    }
}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Txt<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.iter()
            .flat_map(|s| s.iter().copied())
            .for_each(|c| c.hash(state))
    }
}

//--- ParseAll and Compose

impl<Ref: OctetsRef> Parse<Ref> for Txt<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.remaining();
        let text = parser.parse_octets(len)?;
        let mut tmp = Parser::from_ref(text.as_ref());
        while tmp.remaining() != 0 {
            CharStr::skip(&mut tmp)?
        }
        Ok(Txt(text))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Txt<Octets> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(self.0.as_ref())
    }
}

//--- Scan and Display

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for Txt<Octets> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        scanner.scan_charstr_entry().map(Txt)
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Txt<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for slice in self.iter() {
            for ch in slice.iter() {
                fmt::Display::fmt(&Symbol::from_octet(*ch), f)?
            }
        }
        Ok(())
    }
}

//--- Debug

impl<Octets: AsRef<[u8]>> fmt::Debug for Txt<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Txt(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

//--- RtypeRecordData

impl<Octets> RtypeRecordData for Txt<Octets> {
    const RTYPE: Rtype = Rtype::Txt;
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<Octets> serde::Serialize for Txt<Octets>
where
    Octets: AsRef<[u8]> + SerializeOctets,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        struct TxtSeq<'a, Octets>(&'a Txt<Octets>);

        impl<'a, Octets> serde::Serialize for TxtSeq<'a, Octets>
        where
            Octets: AsRef<[u8]> + SerializeOctets,
        {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                let mut serializer = serializer.serialize_seq(None)?;
                for item in self.0.iter_char_strs() {
                    serializer
                        .serialize_element(&format_args!("{}", item))?;
                }
                serializer.end()
            }
        }

        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct("Txt", &TxtSeq(self))
        } else {
            serializer.serialize_newtype_struct(
                "Txt",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octets> serde::Deserialize<'de> for Txt<Octets>
where
    Octets: FromBuilder + DeserializeOctets<'de>,
    <Octets as FromBuilder>::Builder: EmptyBuilder + AsMut<[u8]>,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octets> serde::de::Visitor<'de> for InnerVisitor<'de, Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder + AsMut<[u8]>,
        {
            type Value = Txt<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("TXT record data")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                // This is a non-canonical serialization. We accept strings
                // of any length and break them down into chunks.
                let mut builder =
                    TxtBuilder::<<Octets as FromBuilder>::Builder>::new();
                let mut chars = v.chars();
                while let Some(ch) =
                    Symbol::from_chars(&mut chars).map_err(E::custom)?
                {
                    builder
                        .append_u8(ch.into_octet().map_err(E::custom)?)
                        .map_err(E::custom)?;
                }
                Ok(builder.finish())
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut builder =
                    TxtBuilder::<<Octets as FromBuilder>::Builder>::new();
                while let Some(s) = seq.next_element::<&'de str>()? {
                    builder.append_zone_char_str(s)?;
                }
                Ok(builder.finish())
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    Txt::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    Txt::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octets> serde::de::Visitor<'de> for NewtypeVisitor<Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder + AsMut<[u8]>,
        {
            type Value = Txt<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("TXT record data")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_any(InnerVisitor(Octets::visitor()))
                /*
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octets::visitor()))
                } else {
                    Octets::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octets::visitor()),
                    )
                }
                */
            }
        }

        deserializer
            .deserialize_newtype_struct("Txt", NewtypeVisitor(PhantomData))
    }
}

//------------ TxtCharStrIter ------------------------------------------------

/// An iterator over the character strings of a Txt record.
#[derive(Clone)]
pub struct TxtCharStrIter<'a>(Parser<&'a [u8]>);

impl<'a> Iterator for TxtCharStrIter<'a> {
    type Item = CharStr<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining() == 0 {
            None
        } else {
            Some(CharStr::parse(&mut self.0).unwrap())
        }
    }
}

//------------ TxtIter -------------------------------------------------------

/// An iterator over the character strings of a Txt record.
#[derive(Clone)]
pub struct TxtIter<'a>(TxtCharStrIter<'a>);

impl<'a> Iterator for TxtIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(CharStr::into_octets)
    }
}

//------------ TxtBuilder ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct TxtBuilder<Builder> {
    builder: Builder,

    /// The index of the start of the current char string.
    ///
    /// If this is `None`, there currently is no char string being worked on.
    start: Option<usize>,
}

impl<Builder: OctetsBuilder + EmptyBuilder> TxtBuilder<Builder> {
    pub fn new() -> Self {
        TxtBuilder {
            builder: Builder::empty(),
            start: None,
        }
    }
}

#[cfg(feature = "bytes")]
impl TxtBuilder<BytesMut> {
    pub fn new_bytes() -> Self {
        Self::new()
    }
}

impl<Builder: OctetsBuilder + AsMut<[u8]>> TxtBuilder<Builder> {
    pub fn append_slice(&mut self, mut slice: &[u8]) -> Result<(), ShortBuf> {
        if let Some(start) = self.start {
            let left = 255 - (self.builder.len() - (start + 1));
            if slice.len() < left {
                self.builder.append_slice(slice)?;
                return Ok(());
            }
            let (append, left) = slice.split_at(left);
            self.builder.append_slice(append)?;
            self.builder.as_mut()[start] = 255;
            slice = left;
        }
        for chunk in slice.chunks(255) {
            if self.builder.len() + chunk.len() + 1 >= 0xFFFF {
                return Err(ShortBuf);
            }
            // Remember offset of this incomplete chunk
            self.start = if chunk.len() == 255 {
                None
            } else {
                Some(self.builder.len())
            };
            self.builder.append_slice(&[chunk.len() as u8])?;
            self.builder.append_slice(chunk)?;
        }
        Ok(())
    }

    pub fn append_u8(&mut self, ch: u8) -> Result<(), ShortBuf> {
        self.append_slice(&[ch])
    }

    #[cfg(feature = "serde")]
    fn append_zone_char_str<E: serde::de::Error>(
        &mut self,
        s: &str,
    ) -> Result<(), E> {
        self.close_char_str();
        self.start = Some(self.builder.len());
        self.builder.append_slice(&[0]).map_err(E::custom)?;
        let mut chars = s.chars();
        let mut len = 0;
        while let Some(sym) =
            Symbol::from_chars(&mut chars).map_err(E::custom)?
        {
            if len == 255 {
                return Err(E::custom(CharStrError));
            }
            let sym = sym.into_octet().map_err(E::custom)?;
            self.builder.append_slice(&[sym]).map_err(E::custom)?;
            len += 1;
        }
        self.close_char_str();
        Ok(())
    }

    fn close_char_str(&mut self) {
        if let Some(start) = self.start {
            let last_slice_len = self.builder.len() - (start + 1);
            self.builder.as_mut()[start] = last_slice_len as u8;
        }
    }

    pub fn finish(mut self) -> Txt<Builder::Octets> {
        self.close_char_str();
        Txt(self.builder.freeze())
    }
}

impl<Builder: OctetsBuilder + EmptyBuilder> Default for TxtBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use std::vec::Vec;

    #[test]
    #[cfg(features = "bytes")]
    fn hinfo_octets_into() {
        use crate::octets::OctetsInto;

        let hinfo: Hinfo<Vec<u8>> =
            Hinfo::new("1234".parse().unwrap(), "abcd".parse().unwrap());
        let hinfo_bytes: Hinfo<bytes::Bytes> = hinfo.octets_into().unwrap();
        assert_eq!(hinfo.cpu(), hinfo_bytes.cpu());
        assert_eq!(hinfo.os(), hinfo_bytes.os());
    }

    #[test]
    #[cfg(features = "bytes")]
    fn minfo_octets_into() {
        use crate::base::Dname;
        use crate::octets::OctetsInto;

        let minfo: Minfo<Dname<Vec<u8>>> = Minfo::new(
            "a.example".parse().unwrap(),
            "b.example".parse().unwrap(),
        );
        let minfo_bytes: Minfo<Dname<bytes::Bytes>> =
            minfo.octets_into().unwrap();
        assert_eq!(minfo.rmailbx(), minfo_bytes.rmailbx());
        assert_eq!(minfo.emailbx(), minfo_bytes.emailbx());
    }

    #[test]
    fn txt_from_slice() {
        let short = b"01234";
        let txt: Txt<Vec<u8>> = Txt::from_slice(short).unwrap();
        assert_eq!(Some(&short[..]), txt.as_flat_slice());
        assert_eq!(Ok(short.to_vec()), txt.text::<Vec<u8>>());

        // One full slice
        let full = short.repeat(51);
        let txt: Txt<Vec<u8>> = Txt::from_slice(&full).unwrap();
        assert_eq!(Some(&full[..]), txt.as_flat_slice());
        assert_eq!(Ok(full.to_vec()), txt.text::<Vec<u8>>());

        // Two slices: 255, 5
        let long = short.repeat(52);
        let txt: Txt<Vec<u8>> = Txt::from_slice(&long).unwrap();
        assert_eq!(None, txt.as_flat_slice());
        assert_eq!(Ok(long.to_vec()), txt.text::<Vec<u8>>());

        // Partial
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        for chunk in long.chunks(9) {
            builder.append_slice(chunk).unwrap();
        }
        let txt = builder.finish();
        assert_eq!(None, txt.as_flat_slice());
        assert_eq!(Ok(long.to_vec()), txt.text::<Vec<u8>>());

        // Empty
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        assert!(builder.append_slice(&[]).is_ok());
        let empty = builder.finish();
        assert!(empty.is_empty());
        assert_eq!(0, empty.iter().count());

        // Invalid
        let mut parser = Parser::from_static(b"\x01");
        assert!(Txt::parse(&mut parser).is_err());

        // Too long
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        assert!(builder
            .append_slice(&b"\x00".repeat(std::u16::MAX as usize))
            .is_err());

        // Incremental, reserve space for offsets
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        assert!(builder
            .append_slice(&b"\x00".repeat(std::u16::MAX as usize - 512))
            .is_ok());
        assert!(builder.append_slice(&b"\x00".repeat(512)).is_err());
    }

    #[test]
    fn txt_canonical_compare() {
        let data = [
            "mailru-verification: 14505c6eb222c847",
            "yandex-verification: 6059b187e78de544",
            "v=spf1 include:_spf.protonmail.ch ~all",
            "swisssign-check=CF0JHMTlTDNoES3rrknIRggocffSwqmzMb9X8YbjzK",
            "google-site-verification=aq9zJnp3H3bNE0Y4D4rH5I5Dhj8VMaLYx0uQ7Rozfgg",
            "ahrefs-site-verification_4bdac6bbaa81e0d591d7c0f3ef238905c0521b69bf3d74e64d3775bcb2743afd",
            "brave-ledger-verification=66a7f27fb99949cc0c564ab98efcc58ea1bac3e97eb557c782ab2d44b49aefd7",
        ];

        let records = data
            .iter()
            .map(|e| {
                let mut builder = TxtBuilder::<Vec<u8>>::new();
                builder.append_slice(e.as_bytes()).unwrap();
                builder.finish()
            })
            .collect::<Vec<_>>();

        // The canonical sort must sort by TXT labels which are prefixed by length byte first.
        let mut sorted = records.clone();
        sorted.sort_by(|a, b| a.canonical_cmp(b));

        for (a, b) in records.iter().zip(sorted.iter()) {
            assert_eq!(a, b);
        }
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn txt_ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        let txt = Txt::from_octets(Vec::from(b"\x03foo".as_ref())).unwrap();
        assert_tokens(
            &txt.clone().compact(),
            &[
                Token::NewtypeStruct { name: "Txt" },
                Token::ByteBuf(b"\x03foo"),
            ],
        );
        assert_tokens(
            &txt.readable(),
            &[
                Token::NewtypeStruct { name: "Txt" },
                Token::Seq { len: None },
                Token::BorrowedStr("foo"),
                Token::SeqEnd,
            ],
        );
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn txt_de_str() {
        use serde_test::{assert_de_tokens, Configure, Token};

        assert_de_tokens(
            &Txt::from_octets(Vec::from(b"\x03foo".as_ref()))
                .unwrap()
                .readable(),
            &[
                Token::NewtypeStruct { name: "Txt" },
                Token::BorrowedStr("foo"),
            ],
        );
    }
}
