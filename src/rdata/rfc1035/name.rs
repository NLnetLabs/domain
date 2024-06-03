//! Record data type from RFC 1035 that consist of a single domain name.
//!
//! This is a private module. It’s content is re-exported by the parent.

use crate::base::cmp::CanonicalOrd;
use crate::base::name::{ParsedName, ToName};
use crate::base::wire::ParseError;
use core::{fmt, hash, str};
use core::cmp::Ordering;
use core::str::FromStr;
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;

//------------ Cname --------------------------------------------------------

name_type_well_known! {
    /// CNAME record data.
    ///
    /// The CNAME record specifies the canonical or primary name for domain
    /// name alias.
    ///
    /// The CNAME type is defined in [RFC 1035, section 3.3.1][1].
    /// 
    /// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.1
    (Cname, CNAME, cname, into_cname)
}

//------------ Mb -----------------------------------------------------------

name_type_well_known! {
    /// MB record data.
    ///
    /// The experimental MB record specifies a host that serves a mailbox.
    ///
    /// The MB record type is defined in [RFC 1035, section 3.3.3][1].
    /// 
    /// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.3
    (Mb, MB, madname, into_madname)
}

//------------ Md -----------------------------------------------------------

name_type_well_known! {
    /// MD record data.
    ///
    /// The MD record specifices a host which has a mail agent for
    /// the domain which should be able to deliver mail for the domain.
    ///
    /// The MD record is obsolete. It is recommended to either reject the record
    /// or convert them into an Mx record at preference 0.
    ///
    /// The MD record type is defined in [RFC 1035, section 3.3.4][1].
    /// 
    /// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.4
    (Md, MD, madname, into_madname)
}

//------------ Mf -----------------------------------------------------------

name_type_well_known! {
    /// MF record data.
    ///
    /// The MF record specifices a host which has a mail agent for
    /// the domain which will be accept mail for forwarding to the domain.
    ///
    /// The MF record is obsolete. It is recommended to either reject the record
    /// or convert them into an Mx record at preference 10.
    ///
    /// The MF record type is defined in [RFC 1035, section 3.3.5][1].
    /// 
    /// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.5
    (Mf, MF, madname, into_madname)
}

//------------ Mg -----------------------------------------------------------

name_type_well_known! {
    /// MG record data.
    ///
    /// The MG record specifices a mailbox which is a member of the mail group
    /// specified by the domain name.
    ///
    /// The MG record is experimental.
    ///
    /// The MG record type is defined in [RFC 1035, section 3.3.6][1].
    /// 
    /// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.6
    (Mg, MG, madname, into_madname)
}

//------------ Mr -----------------------------------------------------------

name_type_well_known! {
    /// MR record data.
    ///
    /// The MR record specifices a mailbox which is the proper rename of the
    /// specified mailbox.
    ///
    /// The MR record is experimental.
    ///
    /// The MR record type is defined in [RFC 1035, section 3.3.8][1].
    /// 
    /// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.8
    (Mr, MR, newname, into_newname)
}

//------------ Ns -----------------------------------------------------------

name_type_well_known! {
    /// NS record data.
    ///
    /// NS records specify hosts that are authoritative for a class and domain.
    ///
    /// The NS record type is defined in [RFC 1035, section 3.3.11][1].
    /// 
    /// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.11
    (Ns, NS, nsdname, into_nsdname)
}

//------------ Ptr ----------------------------------------------------------

name_type_well_known! {
    /// PTR record data.
    ///
    /// PRT records are used in special domains to point to some other location
    /// in the domain space.
    ///
    /// The PTR record type is defined in [RFC 1035, section 3.3.12][1].
    /// 
    /// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.12
    (Ptr, PTR, ptrdname, into_ptrdname)
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
    use std::vec::Vec;

    // We only test Cname since all the other types are exactly the same.

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn cname_compose_parse_scan() {
        let rdata =
            Cname::<Name<Vec<u8>>>::from_str("www.example.com").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Cname::parse(parser));
        test_scan(&["www.example.com"], Cname::scan, &rdata);
    }
}

