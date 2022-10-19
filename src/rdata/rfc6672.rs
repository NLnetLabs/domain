use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{ParsedDname, PushError, ToDname};
use crate::base::octets::{
    Compose, EmptyBuilder, FromBuilder, OctetsBuilder, OctetsFrom, OctetsRef,
    Parse, ParseError, Parser, ShortBuf,
};
use crate::base::rdata::RtypeRecordData;
use core::cmp::Ordering;
use core::str::FromStr;
use core::{fmt, hash, ops};

//------------ Dname --------------------------------------------------------

dname_type! {
    /// DNAME record data.
    ///
    /// The DNAME record provides redirection for a subtree of the domain
    /// name tree in the DNS.
    ///
    /// The DNAME type is defined in RFC 6672.
    (Dname, Dname, dname)
}

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use crate::base::name::Dname;
    use crate::rdata::rfc6672;
    use core::str::FromStr;
    use std::vec::Vec;

    #[test]
    fn create_dname() {
        let name = Dname::<Vec<u8>>::from_str("bar.example.com").unwrap();
        let rdata = rfc6672::Dname::new(name.clone());
        assert_eq!(rdata.dname(), &name);
    }
}
