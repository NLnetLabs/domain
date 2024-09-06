//! Record data for the MINFO record.
//!
//! This is a private module. It’s content is re-exported by the parent.

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{FlattenInto, ParsedName, ToName};
use crate::base::rdata::{
    ComposeRecordData, ParseRecordData, RecordData,
};
use crate::base::scan::Scanner;
use crate::base::show::{self, Presenter, Show};
use crate::base::wire::{Composer, ParseError};
use core::fmt;
use core::cmp::Ordering;
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;

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
/// 
/// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.7
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Minfo<N> {
    rmailbx: N,
    emailbx: N,
}

impl Minfo<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::MINFO;
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

    pub(in crate::rdata) fn convert_octets<Target: OctetsFrom<N>>(
        self,
    ) -> Result<Minfo<Target>, Target::Error> {
        Ok(Minfo::new(
            self.rmailbx.try_octets_into()?,
            self.emailbx.try_octets_into()?,
        ))
    }

    pub(in crate::rdata) fn flatten<TargetName>(
        self,
    ) -> Result<Minfo<TargetName>, N::AppendError>
    where N: FlattenInto<TargetName> {
        Ok(Minfo::new(
            self.rmailbx.try_flatten_into()?,
            self.emailbx.try_flatten_into()?,
        ))
    }

    pub fn scan<S: Scanner<Name = N>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(scanner.scan_name()?, scanner.scan_name()?))
    }
}

impl<Octs> Minfo<ParsedName<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            ParsedName::parse(parser)?,
            ParsedName::parse(parser)?,
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
    N: ToName,
    NN: ToName,
{
    fn eq(&self, other: &Minfo<NN>) -> bool {
        self.rmailbx.name_eq(&other.rmailbx)
            && self.emailbx.name_eq(&other.emailbx)
    }
}

impl<N: ToName> Eq for Minfo<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Minfo<NN>> for Minfo<N>
where
    N: ToName,
    NN: ToName,
{
    fn partial_cmp(&self, other: &Minfo<NN>) -> Option<Ordering> {
        match self.rmailbx.name_cmp(&other.rmailbx) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        Some(self.emailbx.name_cmp(&other.emailbx))
    }
}

impl<N: ToName> Ord for Minfo<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.rmailbx.name_cmp(&other.rmailbx) {
            Ordering::Equal => {}
            other => return other,
        }
        self.emailbx.name_cmp(&other.emailbx)
    }
}

impl<N: ToName, NN: ToName> CanonicalOrd<Minfo<NN>> for Minfo<N> {
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
        Minfo::RTYPE
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Minfo<ParsedName<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Minfo::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Name: ToName> ComposeRecordData for Minfo<Name> {
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
            target.append_compressed_name(&self.rmailbx)?;
            target.append_compressed_name(&self.emailbx)
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

//--- Show

impl<N: fmt::Display> Show for Minfo<N> {
    fn show(&self, p: &mut Presenter) -> show::Result {
        p.block(|p| {
            p.write_token(&self.rmailbx)?;
            p.write_comment("responsible mailbox")?;
            p.write_token(&self.emailbx)?;
            p.write_comment("error mailbox")
        })
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::name::Name;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use core::str::FromStr;
    use std::vec::Vec;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn minfo_compose_parse_scan() {
        let rdata = Minfo::<Name<Vec<u8>>>::new(
            Name::from_str("r.example.com").unwrap(),
            Name::from_str("e.example.com").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Minfo::parse(parser));
        test_scan(&["r.example.com", "e.example.com"], Minfo::scan, &rdata);
    }

    #[test]
    fn minfo_octets_into() {
        let minfo: Minfo<Name<Vec<u8>>> = Minfo::new(
            "a.example".parse().unwrap(),
            "b.example".parse().unwrap(),
        );
        let minfo_bytes: Minfo<Name<bytes::Bytes>> =
            minfo.clone().octets_into();
        assert_eq!(minfo.rmailbx(), minfo_bytes.rmailbx());
        assert_eq!(minfo.emailbx(), minfo_bytes.emailbx());
    }
}

