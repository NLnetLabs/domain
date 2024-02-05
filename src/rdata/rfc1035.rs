//! Record data from [RFC 1035]: initial record types.
//!
//! This RFC defines the initial set of record types.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use crate::base::charstr::CharStr;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{FlattenInto, ParsedDname, ToDname};
use crate::base::net::Ipv4Addr;
use crate::base::rdata::{
    ComposeRecordData, LongRecordData, ParseRecordData, RecordData,
};
use crate::base::scan::{Scan, Scanner, ScannerError};
#[cfg(feature = "serde")]
use crate::base::scan::Symbol;
use crate::base::serial::Serial;
use crate::base::wire::{Compose, Composer, FormError, Parse, ParseError};
use crate::base::Ttl;
#[cfg(feature = "bytes")]
use bytes::BytesMut;
use core::cmp::Ordering;
use core::convert::{Infallible, TryFrom};
use core::str::FromStr;
use core::{fmt, hash, str};
use octseq::builder::{
    infallible, EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder,
    ShortBuf,
};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;
#[cfg(feature = "serde")]
use octseq::serde::{DeserializeOctets, SerializeOctets};

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
    #[must_use]
    pub fn new(addr: Ipv4Addr) -> A {
        A { addr }
    }

    /// Creates a new A record from the IPv4 address components.
    #[must_use]
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8) -> A {
        A::new(Ipv4Addr::new(a, b, c, d))
    }

    #[must_use]
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }
    pub fn set_addr(&mut self, addr: Ipv4Addr) {
        self.addr = addr
    }

    pub(super) fn convert_octets<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    pub(super) fn flatten<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>,
    ) -> Result<Self, ParseError> {
        Ipv4Addr::parse(parser).map(Self::new)
    }

    pub fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Error> {
        let token = scanner.scan_octets()?;
        let token = str::from_utf8(token.as_ref())
            .map_err(|_| S::Error::custom("expected IPv4 address"))?;
        A::from_str(token)
            .map_err(|_| S::Error::custom("expected IPv4 address"))
    }
}

//--- OctetsFrom

impl OctetsFrom<A> for A {
    type Error = Infallible;

    fn try_octets_from(source: A) -> Result<Self, Self::Error> {
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

//--- RecordData, ParseRecordData, ComposeRecordData

impl RecordData for A {
    fn rtype(&self) -> Rtype {
        Rtype::A
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> ParseRecordData<'a, Octs> for A {
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::A {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl ComposeRecordData for A {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(4)
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.addr.octets())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
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

dname_type_well_known! {
    /// CNAME record data.
    ///
    /// The CNAME record specifies the canonical or primary name for domain
    /// name alias.
    ///
    /// The CNAME type is defined in RFC 1035, section 3.3.1.
    (Cname, Cname, cname, into_cname)
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
        serialize = "Octs: AsRef<[u8]> + octseq::serde::SerializeOctets",
        deserialize = "Octs: \
                FromBuilder \
                + octseq::serde::DeserializeOctets<'de>, \
            <Octs as FromBuilder>::Builder: AsRef<[u8]> + EmptyBuilder ",
    ))
)]
pub struct Hinfo<Octs> {
    cpu: CharStr<Octs>,
    os: CharStr<Octs>,
}

impl<Octs> Hinfo<Octs> {
    /// Creates a new Hinfo record data from the components.
    pub fn new(cpu: CharStr<Octs>, os: CharStr<Octs>) -> Self {
        Hinfo { cpu, os }
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &CharStr<Octs> {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &CharStr<Octs> {
        &self.os
    }

    pub(super) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Hinfo<Target>, Target::Error> {
        Ok(Hinfo::new(
            self.cpu.try_octets_into()?,
            self.os.try_octets_into()?,
        ))
    }

    pub(super) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Hinfo<Target>, Target::Error> {
        self.convert_octets()
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(CharStr::parse(parser)?, CharStr::parse(parser)?))
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(scanner.scan_charstr()?, scanner.scan_charstr()?))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Hinfo<SrcOcts>> for Hinfo<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Hinfo<SrcOcts>) -> Result<Self, Self::Error> {
        Ok(Hinfo::new(
            CharStr::try_octets_from(source.cpu)?,
            CharStr::try_octets_from(source.os)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Hinfo<Other>> for Hinfo<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Hinfo<Other>) -> bool {
        self.cpu.eq(&other.cpu) && self.os.eq(&other.os)
    }
}

impl<Octs: AsRef<[u8]>> Eq for Hinfo<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Hinfo<Other>> for Hinfo<Octs>
where
    Octs: AsRef<[u8]>,
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

impl<Octs, Other> CanonicalOrd<Hinfo<Other>> for Hinfo<Octs>
where
    Octs: AsRef<[u8]>,
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

impl<Octs: AsRef<[u8]>> Ord for Hinfo<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.cpu.cmp(&other.cpu) {
            Ordering::Equal => {}
            other => return other,
        }
        self.os.cmp(&other.os)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Hinfo<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.cpu.hash(state);
        self.os.hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Hinfo<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::Hinfo
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Hinfo<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Hinfo {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Hinfo<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(self.cpu.compose_len() + self.os.compose_len())
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.cpu.compose(target)?;
        self.os.compose(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for Hinfo<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for Hinfo<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Hinfo")
            .field("cpu", &self.cpu)
            .field("os", &self.os)
            .finish()
    }
}

//------------ Mb -----------------------------------------------------------

dname_type_well_known! {
    /// MB record data.
    ///
    /// The experimental MB record specifies a host that serves a mailbox.
    ///
    /// The MB record type is defined in RFC 1035, section 3.3.3.
    (Mb, Mb, madname, into_madname)
}

//------------ Md -----------------------------------------------------------

dname_type_well_known! {
    /// MD record data.
    ///
    /// The MD record specifices a host which has a mail agent for
    /// the domain which should be able to deliver mail for the domain.
    ///
    /// The MD record is obsolete. It is recommended to either reject the record
    /// or convert them into an Mx record at preference 0.
    ///
    /// The MD record type is defined in RFC 1035, section 3.3.4.
    (Md, Md, madname, into_madname)
}

//------------ Mf -----------------------------------------------------------

dname_type_well_known! {
    /// MF record data.
    ///
    /// The MF record specifices a host which has a mail agent for
    /// the domain which will be accept mail for forwarding to the domain.
    ///
    /// The MF record is obsolete. It is recommended to either reject the record
    /// or convert them into an Mx record at preference 10.
    ///
    /// The MF record type is defined in RFC 1035, section 3.3.5.
    (Mf, Mf, madname, into_madname)
}

//------------ Mg -----------------------------------------------------------

dname_type_well_known! {
    /// MG record data.
    ///
    /// The MG record specifices a mailbox which is a member of the mail group
    /// specified by the domain name.
    ///
    /// The MG record is experimental.
    ///
    /// The MG record type is defined in RFC 1035, section 3.3.6.
    (Mg, Mg, madname, into_madname)
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

    pub(super) fn convert_octets<Target: OctetsFrom<N>>(
        self,
    ) -> Result<Minfo<Target>, Target::Error> {
        Ok(Minfo::new(
            self.rmailbx.try_octets_into()?,
            self.emailbx.try_octets_into()?,
        ))
    }

    pub(super) fn flatten<TargetName>(
        self,
    ) -> Result<Minfo<TargetName>, N::AppendError>
    where N: FlattenInto<TargetName> {
        Ok(Minfo::new(
            self.rmailbx.try_flatten_into()?,
            self.emailbx.try_flatten_into()?,
        ))
    }

    pub fn scan<S: Scanner<Dname = N>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(scanner.scan_dname()?, scanner.scan_dname()?))
    }
}

impl<Octs> Minfo<ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            ParsedDname::parse(parser)?,
            ParsedDname::parse(parser)?,
        ))
    }
}

//--- OctetsFrom and FlattenInto

impl<Name, SrcName> OctetsFrom<Minfo<SrcName>> for Minfo<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(source: Minfo<SrcName>) -> Result<Self, Self::Error> {
        Ok(Minfo::new(
            Name::try_octets_from(source.rmailbx)?,
            Name::try_octets_from(source.emailbx)?,
        ))
    }
}

impl<Name, TName> FlattenInto<Minfo<TName>> for Minfo<Name>
where
    Name: FlattenInto<TName>,
{
    type AppendError = Name::AppendError;

    fn try_flatten_into(self) -> Result<Minfo<TName>, Name::AppendError> {
        self.flatten()
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

//--- RecordData, ParseRecordData, ComposeRecordData

impl<N> RecordData for Minfo<N> {
    fn rtype(&self) -> Rtype {
        Rtype::Minfo
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Minfo<ParsedDname<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Minfo {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Name: ToDname> ComposeRecordData for Minfo<Name> {
    fn rdlen(&self, compress: bool) -> Option<u16> {
        if compress {
            None
        } else {
            Some(self.rmailbx.compose_len() + self.emailbx.compose_len())
        }
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if target.can_compress() {
            target.append_compressed_dname(&self.rmailbx)?;
            target.append_compressed_dname(&self.emailbx)
        } else {
            self.rmailbx.compose(target)?;
            self.emailbx.compose(target)
        }
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.rmailbx.compose_canonical(target)?;
        self.emailbx.compose_canonical(target)
    }
}

//--- Display

impl<N: fmt::Display> fmt::Display for Minfo<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {}.", self.rmailbx, self.emailbx)
    }
}

//------------ Mr -----------------------------------------------------------

dname_type_well_known! {
    /// MR record data.
    ///
    /// The MR record specifices a mailbox which is the proper rename of the
    /// specified mailbox.
    ///
    /// The MR record is experimental.
    ///
    /// The MR record type is defined in RFC 1035, section 3.3.8.
    (Mr, Mr, newname, into_newname)
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

    pub(super) fn convert_octets<Target: OctetsFrom<N>>(
        self,
    ) -> Result<Mx<Target>, Target::Error> {
        Ok(Mx::new(self.preference, self.exchange.try_octets_into()?))
    }

    pub(super) fn flatten<TargetName>(
        self,
    ) -> Result<Mx<TargetName>, N::AppendError>
    where N: FlattenInto<TargetName> {
        Ok(Mx::new(self.preference, self.exchange.try_flatten_into()?))
    }

    pub fn scan<S: Scanner<Dname = N>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(u16::scan(scanner)?, scanner.scan_dname()?))
    }
}

impl<Octs> Mx<ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(u16::parse(parser)?, ParsedDname::parse(parser)?))
    }
}

//--- OctetsFrom and FlattenInto

impl<Name, SrcName> OctetsFrom<Mx<SrcName>> for Mx<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(source: Mx<SrcName>) -> Result<Self, Self::Error> {
        Ok(Mx::new(
            source.preference,
            Name::try_octets_from(source.exchange)?,
        ))
    }
}

impl<Name, TName> FlattenInto<Mx<TName>> for Mx<Name>
where
    Name: FlattenInto<TName>,
{
    type AppendError = Name::AppendError;

    fn try_flatten_into(self) -> Result<Mx<TName>, Name::AppendError> {
        self.flatten()
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

//--- RecordData, ParseRecordData, ComposeRecordData

impl<N> RecordData for Mx<N> {
    fn rtype(&self) -> Rtype {
        Rtype::Mx
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Mx<ParsedDname<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Mx {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Name: ToDname> ComposeRecordData for Mx<Name> {
    fn rdlen(&self, compress: bool) -> Option<u16> {
        if compress {
            None
        } else {
            Some(u16::COMPOSE_LEN + self.exchange.compose_len())
        }
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if target.can_compress() {
            self.preference.compose(target)?;
            target.append_compressed_dname(&self.exchange)
        } else {
            self.preference.compose(target)?;
            self.exchange.compose(target)
        }
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.preference.compose(target)?;
        self.exchange.compose_canonical(target)
    }
}

//--- Display

impl<N: fmt::Display> fmt::Display for Mx<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}.", self.preference, self.exchange)
    }
}

//------------ Ns -----------------------------------------------------------

dname_type_well_known! {
    /// NS record data.
    ///
    /// NS records specify hosts that are authoritative for a class and domain.
    ///
    /// The NS record type is defined in RFC 1035, section 3.3.11.
    (Ns, Ns, nsdname, into_nsdname)
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
pub struct Null<Octs: ?Sized> {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "octseq::serde::SerializeOctets::serialize_octets",
            deserialize_with = "octseq::serde::DeserializeOctets::deserialize_octets",
            bound(
                serialize = "Octs: octseq::serde::SerializeOctets",
                deserialize = "Octs: octseq::serde::DeserializeOctets<'de>",
            )
        )
    )]
    data: Octs,
}

impl<Octs> Null<Octs> {
    /// Creates new NULL record data from the given octets.
    ///
    /// The function will fail if `data` is longer than 65,535 octets.
    pub fn from_octets(data: Octs) -> Result<Self, LongRecordData>
    where
        Octs: AsRef<[u8]>,
    {
        Null::check_slice(data.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(data) })
    }

    /// Creates new NULL record data without checking.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `data` is at most 65,535 octets long.
    pub unsafe fn from_octets_unchecked(data: Octs) -> Self {
        Null { data }
    }
}

impl Null<[u8]> {
    /// Creates new NULL record data from an octets slice.
    ///
    /// The function will fail if `data` is longer than 65,535 octets.
    pub fn from_slice(data: &[u8]) -> Result<&Self, LongRecordData> {
        Self::check_slice(data)?;
        Ok(unsafe { Self::from_slice_unchecked(data) })
    }

    /// Creates new NULL record from an octets slice data without checking.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `data` is at most 65,535 octets long.
    #[must_use]
    pub unsafe fn from_slice_unchecked(data: &[u8]) -> &Self {
        &*(data as *const [u8] as *const Self)
    }

    /// Checks that a slice can be used for NULL record data.
    fn check_slice(slice: &[u8]) -> Result<(), LongRecordData> {
        LongRecordData::check_len(slice.len())
    }
}

impl<Octs: ?Sized> Null<Octs> {
    /// The raw content of the record.
    pub fn data(&self) -> &Octs {
        &self.data
    }
}

impl<Octs: AsRef<[u8]>> Null<Octs> {
    pub fn len(&self) -> usize {
        self.data.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.as_ref().is_empty()
    }
}

impl<Octs> Null<Octs> {
    pub(super) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Null<Target>, Target::Error> {
        Ok(unsafe {
            Null::from_octets_unchecked(self.data.try_octets_into()?)
        })
    }

    pub(super) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Null<Target>, Target::Error> {
        self.convert_octets()
    }
}

impl<Octs> Null<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        parser
            .parse_octets(len)
            .map(|res| unsafe { Self::from_octets_unchecked(res) })
            .map_err(Into::into)
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Null<SrcOcts>> for Null<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Null<SrcOcts>) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.data)
            .map(|res| unsafe { Self::from_octets_unchecked(res) })
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Null<Other>> for Null<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &Null<Other>) -> bool {
        self.data.as_ref().eq(other.data.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for Null<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Null<Other>> for Null<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &Null<Other>) -> Option<Ordering> {
        self.data.as_ref().partial_cmp(other.data.as_ref())
    }
}

impl<Octs, Other> CanonicalOrd<Null<Other>> for Null<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn canonical_cmp(&self, other: &Null<Other>) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Ord for Null<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for Null<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.data.as_ref().hash(state)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs: ?Sized> RecordData for Null<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::Null
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Null<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Null {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> ComposeRecordData for Null<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u16::try_from(self.data.as_ref().len()).expect("long NULL rdata"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.data.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- AsRef

impl<Octs: AsRef<Other>, Other> AsRef<Other> for Null<Octs> {
    fn as_ref(&self) -> &Other {
        self.data.as_ref()
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]>> fmt::Display for Null<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data.as_ref().len())?;
        for ch in self.data.as_ref().iter() {
            write!(f, " {:02x}", ch)?;
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> fmt::Debug for Null<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Null(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

//------------ Ptr ----------------------------------------------------------

dname_type_well_known! {
    /// PTR record data.
    ///
    /// PRT records are used in special domains to point to some other location
    /// in the domain space.
    ///
    /// The PTR record type is defined in RFC 1035, section 3.3.12.
    (Ptr, Ptr, ptrdname, into_ptrdname)
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
    refresh: Ttl,
    retry: Ttl,
    expire: Ttl,
    minimum: Ttl,
}

impl<N> Soa<N> {
    /// Creates new Soa record data from content.
    pub fn new(
        mname: N,
        rname: N,
        serial: Serial,
        refresh: Ttl,
        retry: Ttl,
        expire: Ttl,
        minimum: Ttl,
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

    /// The time interval before the zone should be refreshed.
    pub fn refresh(&self) -> Ttl {
        self.refresh
    }

    /// The time before a failed refresh is retried.
    pub fn retry(&self) -> Ttl {
        self.retry
    }

    /// The upper limit of time the zone is authoritative.
    pub fn expire(&self) -> Ttl {
        self.expire
    }

    /// The minimum TTL to be exported with any RR from this zone.
    pub fn minimum(&self) -> Ttl {
        self.minimum
    }

    pub(super) fn convert_octets<Target: OctetsFrom<N>>(
        self,
    ) -> Result<Soa<Target>, Target::Error> {
        Ok(Soa::new(
            self.mname.try_octets_into()?,
            self.rname.try_octets_into()?,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        ))
    }

    pub(super) fn flatten<TargetName>(
        self,
    ) -> Result<Soa<TargetName>, N::AppendError>
    where N: FlattenInto<TargetName> {
        Ok(Soa::new(
            self.mname.try_flatten_into()?,
            self.rname.try_flatten_into()?,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        ))
    }

    pub fn scan<S: Scanner<Dname = N>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(
            scanner.scan_dname()?,
            scanner.scan_dname()?,
            Serial::scan(scanner)?,
            Ttl::scan(scanner)?,
            Ttl::scan(scanner)?,
            Ttl::scan(scanner)?,
            Ttl::scan(scanner)?,
        ))
    }
}

impl<Octs> Soa<ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            ParsedDname::parse(parser)?,
            ParsedDname::parse(parser)?,
            Serial::parse(parser)?,
            Ttl::parse(parser)?,
            Ttl::parse(parser)?,
            Ttl::parse(parser)?,
            Ttl::parse(parser)?,
        ))
    }
}

//--- OctetsFrom and FlattenInto

impl<Name, SrcName> OctetsFrom<Soa<SrcName>> for Soa<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(source: Soa<SrcName>) -> Result<Self, Self::Error> {
        Ok(Soa::new(
            Name::try_octets_from(source.mname)?,
            Name::try_octets_from(source.rname)?,
            source.serial,
            source.refresh,
            source.retry,
            source.expire,
            source.minimum,
        ))
    }
}

impl<Name, TName> FlattenInto<Soa<TName>> for Soa<Name>
where
    Name: FlattenInto<TName>,
{
    type AppendError = Name::AppendError;

    fn try_flatten_into(self) -> Result<Soa<TName>, Name::AppendError> {
        self.flatten()
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

//--- RecordData, ParseRecordData, ComposeRecordData

impl<N> RecordData for Soa<N> {
    fn rtype(&self) -> Rtype {
        Rtype::Soa
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Soa<ParsedDname<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Soa {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Name: ToDname> ComposeRecordData for Soa<Name> {
    fn rdlen(&self, compress: bool) -> Option<u16> {
        if compress {
            None
        } else {
            Some(
                self.mname.compose_len()
                    + self.rname.compose_len()
                    + Serial::COMPOSE_LEN
                    + 4 * u32::COMPOSE_LEN,
            )
        }
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if target.can_compress() {
            target.append_compressed_dname(&self.mname)?;
            target.append_compressed_dname(&self.rname)?;
        } else {
            self.mname.compose(target)?;
            self.rname.compose(target)?;
        }
        self.compose_fixed(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.mname.compose_canonical(target)?;
        self.rname.compose_canonical(target)?;
        self.compose_fixed(target)
    }
}

impl<Name: ToDname> Soa<Name> {
    fn compose_fixed<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.serial.compose(target)?;
        self.refresh.compose(target)?;
        self.retry.compose(target)?;
        self.expire.compose(target)?;
        self.minimum.compose(target)
    }
}

//--- Display

impl<N: fmt::Display> fmt::Display for Soa<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}. {}. {} {} {} {} {}",
            self.mname,
            self.rname,
            self.serial,
            self.refresh.as_secs(),
            self.retry.as_secs(),
            self.expire.as_secs(),
            self.minimum.as_secs()
        )
    }
}

//------------ Txt ----------------------------------------------------------

/// Txt record data.
///
/// Txt records hold descriptive text.
///
/// The Txt record type is defined in RFC 1035, section 3.3.14.
#[derive(Clone)]
pub struct Txt<Octs: ?Sized>(Octs);

impl<Octs: FromBuilder> Txt<Octs> {
    /// Creates a new Txt record from a single character string.
    pub fn build_from_slice(text: &[u8]) -> Result<Self, ShortBuf>
    where
        <Octs as FromBuilder>::Builder:
            EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    {
        let mut builder = TxtBuilder::<Octs::Builder>::new();
        builder.append_slice(text)?;
        Ok(builder.finish())
    }
}

impl<Octs> Txt<Octs> {
    /// Creates new TXT record data from its encoded content.
    pub fn from_octets(octets: Octs) -> Result<Self, TxtError>
    where
        Octs: AsRef<[u8]>,
    {
        Txt::check_slice(octets.as_ref())?;
        Ok(unsafe { Txt::from_octets_unchecked(octets) })
    }

    /// Creates new TXT record data without checking.
    ///
    /// # Safety
    ///
    /// The passed octets must contain correctly encoded TXT record data,
    /// that is a sequence of encoded character strings.
    unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Txt(octets)
    }
}

impl Txt<[u8]> {
    /// Creates new TXT record data on an octets slice.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, TxtError> {
        Txt::check_slice(slice)?;
        Ok(unsafe { Txt::from_slice_unchecked(slice) })
    }

    /// Creates new TXT record data on an octets slice without checking.
    ///
    /// # Safety
    ///
    /// The passed octets must contain correctly encoded TXT record data,
    /// that is a sequence of encoded character strings.
    unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        unsafe { &*(slice as *const [u8] as *const Self) }
    }

    /// Checks that a slice contains correctly encoded TXT data.
    fn check_slice(mut slice: &[u8]) -> Result<(), TxtError> {
        LongRecordData::check_len(slice.len())?;
        while let Some(&len) = slice.first() {
            let len = usize::from(len);
            if slice.len() <= len {
                return Err(TxtError(TxtErrorInner::ShortInput));
            }
            slice = &slice[len + 1..];
        }
        Ok(())
    }
}

impl<Octs> Txt<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError>
    where
        Octs: AsRef<[u8]>,
    {
        let len = parser.remaining();
        let text = parser.parse_octets(len)?;
        let mut tmp = Parser::from_ref(text.as_ref());
        while tmp.remaining() != 0 {
            CharStr::skip(&mut tmp)?
        }
        Ok(Txt(text))
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        scanner.scan_charstr_entry().map(Txt)
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Txt<Octs> {
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

    /// Returns the content if it consists of a single character string.
    pub fn as_flat_slice(&self) -> Option<&[u8]> {
        if usize::from(self.0.as_ref()[0]) == self.0.as_ref().len() - 1 {
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
    pub fn try_text<T: FromBuilder>(
        &self,
    ) -> Result<T, <<T as FromBuilder>::Builder as OctetsBuilder>::AppendError>
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

    pub fn text<T: FromBuilder>(&self) -> T
    where
        <T as FromBuilder>::Builder: EmptyBuilder,
        <<T as FromBuilder>::Builder as OctetsBuilder>::AppendError:
            Into<Infallible>,
    {
        infallible(self.try_text())
    }
}

impl<SrcOcts> Txt<SrcOcts> {
    pub(super) fn convert_octets<Target: OctetsFrom<SrcOcts>>(
        self,
    ) -> Result<Txt<Target>, Target::Error> {
        Ok(Txt(self.0.try_octets_into()?))
    }

    pub(super) fn flatten<Octs: OctetsFrom<SrcOcts>>(
        self,
    ) -> Result<Txt<Octs>, Octs::Error> {
        self.convert_octets()
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Txt<SrcOcts>> for Txt<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Txt<SrcOcts>) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.0).map(Self)
    }
}

//--- IntoIterator

impl<'a, Octs: AsRef<[u8]>> IntoIterator for &'a Txt<Octs> {
    type Item = &'a [u8];
    type IntoIter = TxtIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Txt<Other>> for Txt<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Txt<Other>) -> bool {
        self.iter()
            .flat_map(|s| s.iter().copied())
            .eq(other.iter().flat_map(|s| s.iter().copied()))
    }
}

impl<Octs: AsRef<[u8]>> Eq for Txt<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Txt<Other>> for Txt<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Txt<Other>) -> Option<Ordering> {
        self.iter()
            .flat_map(|s| s.iter().copied())
            .partial_cmp(other.iter().flat_map(|s| s.iter().copied()))
    }
}

impl<Octs, Other> CanonicalOrd<Txt<Other>> for Txt<Octs>
where
    Octs: AsRef<[u8]>,
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

impl<Octs: AsRef<[u8]>> Ord for Txt<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter()
            .flat_map(|s| s.iter().copied())
            .cmp(other.iter().flat_map(|s| s.iter().copied()))
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Txt<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.iter()
            .flat_map(|s| s.iter().copied())
            .for_each(|c| c.hash(state))
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Txt<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::Txt
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Txt<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Txt {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Txt<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(u16::try_from(self.0.as_ref().len()).expect("long TXT rdata"))
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.0.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for Txt<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for slice in self.iter_char_strs() {
            if !first {
                f.write_str(" ")?;
            }
            else {
                first = false;
            }
            write!(f, "{}", slice.display_quoted())?;
        }
        Ok(())
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for Txt<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Txt(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<Octs> serde::Serialize for Txt<Octs>
where
    Octs: AsRef<[u8]> + SerializeOctets,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        struct TxtSeq<'a, Octs>(&'a Txt<Octs>);

        impl<'a, Octs> serde::Serialize for TxtSeq<'a, Octs>
        where
            Octs: AsRef<[u8]> + SerializeOctets,
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
impl<'de, Octs> serde::Deserialize<'de> for Txt<Octs>
where
    Octs: FromBuilder + DeserializeOctets<'de>,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octs> serde::de::Visitor<'de> for InnerVisitor<'de, Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
        {
            type Value = Txt<Octs>;

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
                    TxtBuilder::<<Octs as FromBuilder>::Builder>::new();
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
                    TxtBuilder::<<Octs as FromBuilder>::Builder>::new();
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

        impl<'de, Octs> serde::de::Visitor<'de> for NewtypeVisitor<Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
        {
            type Value = Txt<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("TXT record data")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_any(InnerVisitor(Octs::visitor()))
                /*
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octs::visitor()))
                } else {
                    Octs::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octs::visitor()),
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
pub struct TxtCharStrIter<'a>(Parser<'a, [u8]>);

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
    #[must_use]
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

impl<Builder: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> TxtBuilder<Builder> {
    fn builder_append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.builder.append_slice(slice).map_err(Into::into)
    }

    pub fn append_slice(&mut self, mut slice: &[u8]) -> Result<(), ShortBuf> {
        if let Some(start) = self.start {
            let left = 255 - (self.builder.as_ref().len() - (start + 1));
            if slice.len() < left {
                self.builder_append_slice(slice)?;
                return Ok(());
            }
            let (append, left) = slice.split_at(left);
            self.builder_append_slice(append)?;
            self.builder.as_mut()[start] = 255;
            slice = left;
        }
        for chunk in slice.chunks(255) {
            if self.builder.as_ref().len() + chunk.len() + 1 >= 0xFFFF {
                return Err(ShortBuf);
            }
            // Remember offset of this incomplete chunk
            self.start = if chunk.len() == 255 {
                None
            } else {
                Some(self.builder.as_ref().len())
            };
            self.builder_append_slice(&[chunk.len() as u8])?;
            self.builder_append_slice(chunk)?;
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
        use crate::base::charstr::CharStrError;

        self.close_char_str();
        self.start = Some(self.builder.as_ref().len());
        self.builder_append_slice(&[0]).map_err(E::custom)?;
        let mut len = 0;
        let mut chars = s.chars();
        while let Some(sym) =
            Symbol::from_chars(&mut chars).map_err(E::custom)?
        {
            if len == 255 {
                return Err(E::custom(CharStrError));
            }
            let sym = sym.into_octet().map_err(E::custom)?;
            self.builder_append_slice(&[sym]).map_err(E::custom)?;
            len += 1;
        }
        self.close_char_str();
        Ok(())
    }

    fn close_char_str(&mut self) {
        if let Some(start) = self.start {
            let last_slice_len = self.builder.as_ref().len() - (start + 1);
            self.builder.as_mut()[start] = last_slice_len as u8;
        }
    }

    pub fn finish(mut self) -> Txt<Builder::Octets>
    where
        Builder: FreezeBuilder,
    {
        self.close_char_str();
        Txt(self.builder.freeze())
    }
}

impl<Builder: OctetsBuilder + EmptyBuilder> Default for TxtBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//============ Error Types ===================================================

//------------ TxtError ------------------------------------------------------

/// An octets sequence does not form valid TXT record data.
#[derive(Clone, Copy, Debug)]
pub struct TxtError(TxtErrorInner);

#[derive(Clone, Copy, Debug)]
enum TxtErrorInner {
    Long(LongRecordData),
    ShortInput,
}

impl TxtError {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self.0 {
            TxtErrorInner::Long(err) => err.as_str(),
            TxtErrorInner::ShortInput => "short input",
        }
    }
}

impl From<LongRecordData> for TxtError {
    fn from(err: LongRecordData) -> TxtError {
        TxtError(TxtErrorInner::Long(err))
    }
}

impl From<TxtError> for FormError {
    fn from(err: TxtError) -> FormError {
        FormError::new(err.as_str())
    }
}

impl fmt::Display for TxtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::name::Dname;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use octseq::octets::OctetsInto;
    use std::vec::Vec;

    //--- A

    #[test]
    fn a_compose_parse_scan() {
        let rdata = A::from_octets(1, 2, 3, 4);
        test_rdlen(&rdata);
        test_compose_parse(&rdata, A::parse);
        test_scan(&["1.2.3.4"], A::scan, &rdata);
    }

    //--- Cname
    //
    // This covers all the other generated types, too.

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn cname_compose_parse_scan() {
        let rdata =
            Cname::<Dname<Vec<u8>>>::from_str("www.example.com").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Cname::parse(parser));
        test_scan(&["www.example.com"], Cname::scan, &rdata);
    }

    //--- Hinfo

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn hinfo_compose_parse_scan() {
        let rdata = Hinfo::new(
            CharStr::from_octets("cpu").unwrap(),
            CharStr::from_octets("os").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Hinfo::parse(parser));
        test_scan(&["cpu", "os"], Hinfo::scan, &rdata);
    }

    #[test]
    fn hinfo_octets_into() {
        let hinfo: Hinfo<Vec<u8>> =
            Hinfo::new("1234".parse().unwrap(), "abcd".parse().unwrap());
        let hinfo_bytes: Hinfo<bytes::Bytes> = hinfo.clone().octets_into();
        assert_eq!(hinfo.cpu(), hinfo_bytes.cpu());
        assert_eq!(hinfo.os(), hinfo_bytes.os());
    }

    //--- Minfo

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn minfo_compose_parse_scan() {
        let rdata = Minfo::<Dname<Vec<u8>>>::new(
            Dname::from_str("r.example.com").unwrap(),
            Dname::from_str("e.example.com").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Minfo::parse(parser));
        test_scan(&["r.example.com", "e.example.com"], Minfo::scan, &rdata);
    }

    #[test]
    fn minfo_octets_into() {
        let minfo: Minfo<Dname<Vec<u8>>> = Minfo::new(
            "a.example".parse().unwrap(),
            "b.example".parse().unwrap(),
        );
        let minfo_bytes: Minfo<Dname<bytes::Bytes>> =
            minfo.clone().octets_into();
        assert_eq!(minfo.rmailbx(), minfo_bytes.rmailbx());
        assert_eq!(minfo.emailbx(), minfo_bytes.emailbx());
    }

    //--- Mx

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn mx_compose_parse_scan() {
        let rdata = Mx::<Dname<Vec<u8>>>::new(
            12,
            Dname::from_str("mail.example.com").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Mx::parse(parser));
        test_scan(&["12", "mail.example.com"], Mx::scan, &rdata);
    }

    //--- Null

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn null_compose_parse_scan() {
        let rdata = Null::from_octets("foo").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Null::parse(parser));
    }

    //--- Soa

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn soa_compose_parse_scan() {
        let rdata = Soa::<Dname<Vec<u8>>>::new(
            Dname::from_str("m.example.com").unwrap(),
            Dname::from_str("r.example.com").unwrap(),
            Serial(11),
            Ttl::from_secs(12),
            Ttl::from_secs(13),
            Ttl::from_secs(14),
            Ttl::from_secs(15),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Soa::parse(parser));
        test_scan(
            &[
                "m.example.com",
                "r.example.com",
                "11",
                "12",
                "13",
                "14",
                "15",
            ],
            Soa::scan,
            &rdata,
        );
    }

    //--- Txt

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn txt_compose_parse_scan() {
        let rdata = Txt::from_octets(b"\x03foo\x03bar".as_ref()).unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Txt::parse(parser));
        test_scan(&["foo", "bar"], Txt::scan, &rdata);
    }

    #[test]
    fn txt_from_slice() {
        let short = b"01234";
        let txt: Txt<Vec<u8>> = Txt::build_from_slice(short).unwrap();
        assert_eq!(Some(&short[..]), txt.as_flat_slice());
        assert_eq!(short.to_vec(), txt.text::<Vec<u8>>());

        // One full slice
        let full = short.repeat(51);
        let txt: Txt<Vec<u8>> = Txt::build_from_slice(&full).unwrap();
        assert_eq!(Some(&full[..]), txt.as_flat_slice());
        assert_eq!(full.to_vec(), txt.text::<Vec<u8>>());

        // Two slices: 255, 5
        let long = short.repeat(52);
        let txt: Txt<Vec<u8>> = Txt::build_from_slice(&long).unwrap();
        assert_eq!(None, txt.as_flat_slice());
        assert_eq!(long.to_vec(), txt.text::<Vec<u8>>());

        // Partial
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        for chunk in long.chunks(9) {
            builder.append_slice(chunk).unwrap();
        }
        let txt = builder.finish();
        assert_eq!(None, txt.as_flat_slice());
        assert_eq!(long.to_vec(), txt.text::<Vec<u8>>());

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
            "google-site-\
                verification=aq9zJnp3H3bNE0Y4D4rH5I5Dhj8VMaLYx0uQ7Rozfgg",
            "ahrefs-site-verification_\
                4bdac6bbaa81e0d591d7c0f3ef238905c0521b69bf3d74e64d3775bc\
                b2743afd",
            "brave-ledger-verification=\
                66a7f27fb99949cc0c564ab98efcc58ea1bac3e97eb557c782ab2d44b\
                49aefd7",
        ];

        let records = data
            .iter()
            .map(|e| {
                let mut builder = TxtBuilder::<Vec<u8>>::new();
                builder.append_slice(e.as_bytes()).unwrap();
                builder.finish()
            })
            .collect::<Vec<_>>();

        // The canonical sort must sort by TXT labels which are prefixed by
        // length byte first.
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

    #[test]
    fn txt_display() {
        fn cmp(input: &[u8], output: &str) {
            assert_eq!(
                format!("{}", Txt::from_octets(input).unwrap()),
                output
            );
        }

        cmp(b"\x03foo", "\"foo\"");
        cmp(b"\x03foo\x03bar", "\"foo\" \"bar\"");
        cmp(b"\x03fo\"\x04bar ", "\"fo\\\"\" \"bar \"");
        // I don’t think we need more escaping tests since the impl defers
        // to CharStr::display_quoted which is tested ...
    }
}
