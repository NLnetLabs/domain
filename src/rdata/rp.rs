//! Record data for the RP record.
//!
//! "The purpose of this [resource record type] is to provide a standard
//! method for associating responsible person identification to any name in
//! the DNS" [1].
//!
//! The RP record type is defined in [RFC 1183, section 2.2][2].
//!
//! [1]: https://datatracker.ietf.org/doc/html/rfc1183#section-2
//! [2]: https://datatracker.ietf.org/doc/html/rfc1183#section-2.2

use core::cmp::Ordering;
use core::fmt;

use octseq::{Octets, OctetsFrom, OctetsInto, Parser};

use crate::base::name::FlattenInto;
use crate::base::rdata::ComposeRecordData;
use crate::base::scan::Scanner;
use crate::base::wire::{Composer, ParseError};
use crate::base::zonefile_fmt::{self, Formatter, ZonefileFmt};
use crate::base::{
    CanonicalOrd, ParseRecordData, ParsedName, RecordData, Rtype, ToName,
};

/// The Responsible Person Resource Record identifies responsible persons for
/// any name in the DNS.
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Rp<N> {
    /// The mailbox for the responsible person in domain name format (like
    /// with SOA).
    mbox: N,

    /// The domain name of a TXT record holding human-readable information
    /// about the responsible person.
    txt: N,
}

impl<N> Rp<N> {
    pub fn new(mbox: N, txt: N) -> Self {
        Self { mbox, txt }
    }

    pub fn mbox(&self) -> &N {
        &self.mbox
    }

    pub fn txt(&self) -> &N {
        &self.txt
    }

    pub(in crate::rdata) fn convert_octets<Target: OctetsFrom<N>>(
        self,
    ) -> Result<Rp<Target>, Target::Error> {
        Ok(Rp::new(
            self.mbox.try_octets_into()?,
            self.txt.try_octets_into()?,
        ))
    }

    pub(in crate::rdata) fn flatten<TargetName>(
        self,
    ) -> Result<Rp<TargetName>, N::AppendError>
    where
        N: FlattenInto<TargetName>,
    {
        Ok(Rp::new(
            self.mbox.try_flatten_into()?,
            self.txt.try_flatten_into()?,
        ))
    }

    pub fn scan<S: Scanner<Name = N>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(scanner.scan_name()?, scanner.scan_name()?))
    }
}

impl<Octs> Rp<ParsedName<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            ParsedName::parse(parser)?,
            ParsedName::parse(parser)?,
        ))
    }
}

impl Rp<()> {
    pub(crate) const RTYPE: Rtype = Rtype::RP;
}

//--- OctetsFrom and FlattenInto

impl<Name, SrcName> OctetsFrom<Rp<SrcName>> for Rp<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(source: Rp<SrcName>) -> Result<Self, Self::Error> {
        Ok(Rp::new(
            Name::try_octets_from(source.mbox)?,
            Name::try_octets_from(source.txt)?,
        ))
    }
}

impl<Name, TName> FlattenInto<Rp<TName>> for Rp<Name>
where
    Name: FlattenInto<TName>,
{
    type AppendError = Name::AppendError;

    fn try_flatten_into(self) -> Result<Rp<TName>, Name::AppendError> {
        self.flatten()
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Rp<NN>> for Rp<N>
where
    N: ToName,
    NN: ToName,
{
    fn eq(&self, other: &Rp<NN>) -> bool {
        self.mbox.name_eq(&other.mbox) && self.txt.name_eq(&other.txt)
    }
}

impl<N: ToName> Eq for Rp<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Rp<NN>> for Rp<N>
where
    N: ToName,
    NN: ToName,
{
    fn partial_cmp(&self, other: &Rp<NN>) -> Option<Ordering> {
        match self.mbox.name_cmp(&other.mbox) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        Some(self.txt.name_cmp(&other.txt))
    }
}

impl<N: ToName> Ord for Rp<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.mbox.name_cmp(&other.mbox) {
            Ordering::Equal => {}
            other => return other,
        }
        self.txt.name_cmp(&other.txt)
    }
}

impl<N: ToName, NN: ToName> CanonicalOrd<Rp<NN>> for Rp<N> {
    fn canonical_cmp(&self, other: &Rp<NN>) -> Ordering {
        match self.mbox.lowercase_composed_cmp(&other.mbox) {
            Ordering::Equal => {}
            other => return other,
        }
        self.txt.lowercase_composed_cmp(&other.txt)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<N> RecordData for Rp<N> {
    fn rtype(&self) -> Rtype {
        Rp::RTYPE
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Rp<ParsedName<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rp::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Name: ToName> ComposeRecordData for Rp<Name> {
    fn rdlen(&self, compress: bool) -> Option<u16> {
        if compress {
            None
        } else {
            Some(self.mbox.compose_len() + self.txt.compose_len())
        }
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if target.can_compress() {
            target.append_compressed_name(&self.mbox)?;
            target.append_compressed_name(&self.txt)
        } else {
            self.mbox.compose(target)?;
            self.txt.compose(target)
        }
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.mbox.compose_canonical(target)?;
        self.txt.compose_canonical(target)
    }
}

//--- Display

impl<N: fmt::Display> fmt::Display for Rp<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}. {}.", self.mbox, self.txt,)
    }
}

impl<N: ToName> ZonefileFmt for Rp<N> {
    fn fmt(&self, p: &mut impl Formatter) -> zonefile_fmt::Result {
        p.block(|p| {
            p.write_token(self.mbox.fmt_with_dot())?;
            p.write_comment("mbox-dname")?;
            p.write_token(self.txt.fmt_with_dot())?;
            p.write_comment("txt-dname")
        })
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use octseq::Array;

    use super::*;
    use crate::base::iana::Class;
    use crate::base::name::Name;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use crate::zonefile::inplace::{self, Zonefile};
    use core::str::FromStr;
    use std::vec::Vec;

    type Octets512 = Array<512>;
    type Dname512 = Name<Array<512>>;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn rp_compose_parse_scan() {
        let rdata = Rp::<Name<Vec<u8>>>::new(
            Name::from_str("mbox.example.com").unwrap(),
            Name::from_str("some-person.example.com").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Rp::parse(parser));
        test_scan(
            &["mbox.example.com", "some-person.example.com"],
            Rp::scan,
            &rdata,
        );
    }

    #[cfg(feature = "zonefile")]
    #[test]
    fn rp_parse_zonefile() {
        use crate::base::Name;
        use crate::rdata::ZoneRecordData;
        use crate::zonefile::inplace::{Entry, Zonefile};

        let content = r#"
example.      86400  IN  SOA     ns1 admin 2018031900 (
                                 1800 900 604800 86400 )
              86400  IN  NS      ns1
              86400  IN  NS      ns2
              86400  IN  RP      mbox.example. some-user.example.
ns1           3600   IN  A       203.0.113.63
ns2           3600   IN  AAAA    2001:db8::63
"#;

        let mut zone = Zonefile::load(&mut content.as_bytes()).unwrap();
        zone.set_origin(Name::root());
        while let Some(entry) = zone.next_entry().unwrap() {
            match entry {
                Entry::Record(record) => {
                    if record.rtype() != Rtype::RP {
                        continue;
                    }
                    match record.into_data() {
                        ZoneRecordData::Rp(_) => {}
                        _ => panic!(),
                    }
                }
                _ => panic!(),
            }
        }
    }

    #[track_caller]
    /// A helper function that takes a single resource record in zonefile
    /// format as input for the Zonefile parser, and compares it to the
    /// expected rdata octets.
    fn rp_zonefile_parse_expect(
        rr: impl AsRef<[u8]>,
        expected: impl AsRef<[u8]>,
    ) {
        let mut zonefile = Zonefile::from(rr.as_ref());
        zonefile.set_default_class(Class::IN);
        let inplace::Entry::Record(scanned_rr) =
            zonefile.next_entry().unwrap().unwrap()
        else {
            panic!()
        };

        let mut buf = Octets512::new();
        if let crate::rdata::ZoneRecordData::Rp(scanned_rdata) =
            scanned_rr.data()
        {
            scanned_rdata.compose_rdata(&mut buf).unwrap();
        } else {
            panic!()
        }

        assert_eq!(buf.as_ref(), expected.as_ref());
    }

    #[test]
    fn rp_test_root_for_disabled_field() {
        rp_zonefile_parse_expect(b"example.com.   RP   . .\n", b"\x00\x00")
    }

    #[test]
    fn rp_test_root_for_escaped_field() {
        rp_zonefile_parse_expect(
            b"example.com.   RP   a\\.b.example. txt.\n",
            b"\x03a.b\x07example\x00\x03txt\x00",
        )
    }
}
