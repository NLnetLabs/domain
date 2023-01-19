use crate::base::cmp::CanonicalOrd;
use crate::base::name::{ParsedDname, PushError, ToDname};
use crate::base::wire::ParseError;
use core::cmp::Ordering;
use core::str::FromStr;
use core::{fmt, hash, ops};
use octseq::builder::{EmptyBuilder, FromBuilder};
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;

//------------ Dname --------------------------------------------------------

dname_type_canonical! {
    /// DNAME record data.
    ///
    /// The DNAME record provides redirection for a subtree of the domain
    /// name tree in the DNS.
    ///
    /// The DNAME type is defined in RFC 6672.
    (Dname, Dname, dname, into_dname)
}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::name::Dname as Name;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use core::str::FromStr;
    use std::vec::Vec;

    #[test]
    fn create_dname() {
        let name = Name::<Vec<u8>>::from_str("bar.example.com").unwrap();
        let rdata = Dname::new(name.clone());
        assert_eq!(rdata.dname(), &name);
    }
    // This covers all the other generated types, too.

    #[test]
    fn dname_compose_parse_scan() {
        let rdata =
            Dname::<Name<Vec<u8>>>::from_str("www.example.com").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Dname::parse(parser));
        test_scan(&["www.example.com"], Dname::scan, &rdata);
    }
}
