//! Record types relating to DNSSEC.

use core::fmt;

use domain_macros::*;

//----------- Submodules -----------------------------------------------------

mod dnskey;
pub use dnskey::{DNSKey, DNSKeyFlags};

mod rrsig;
pub use rrsig::Rrsig;

mod nsec;
pub use nsec::{Nsec, TypeBitmaps};

mod nsec3;
pub use nsec3::{Nsec3, Nsec3Flags, Nsec3HashAlgorithm, Nsec3Param};

mod ds;
pub use ds::{DigestType, Ds};

//----------- SecAlg ---------------------------------------------------------

/// A cryptographic algorithm for DNS security.
///
/// IANA maintains [the registry][iana-secalg] of assignments for Security
/// Algorithms.
///
/// [iana-secalg]: https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct SecAlg {
    /// The algorithm code.
    pub code: u8,
}

impl SecAlg {
    /// Create a new [`SecAlg`].
    pub const fn new(value: u8) -> Self {
        Self { code: value }
    }
}

//--- Associated Constants

known_values_define! (
    SecAlg::(pub ALGS, pub MNEMONICS) = [
        /// The DSA/SHA-1 algorithm.
        "DSA" as DSA_SHA1 = Self { code: 3 },

        /// The RSA/SHA-1 algorithm.
        "RSASHA1" as RSA_SHA1 = Self { code: 5 },
    ];
);

//--- Conversion to and from 'u8'

known_values_from_and_to_primitive!(SecAlg, u8);

//--- Formatting

/// Format a [`SecAlg`] for debugging.
///
/// The output displays the mnemonic, if known, and the code associated to the
/// [`SecAlg`].
///
/// ```
/// # use domain::new::rdata::SecAlg;
/// // Known Security Algorithm.
/// assert_eq!("SecAlg::DSA(3)", format!("{:?}", SecAlg::DSA_SHA1));
/// // Unknown Security Algorithm.
/// assert_eq!("SecAlg(42)", format!("{:?}", SecAlg::from(42)));
/// ```
impl fmt::Debug for SecAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "SecAlg::{}({})", m, self.code),
            None => write!(f, "SecAlg({})", self.code),
        }
    }
}

/// Format a [`SecAlg`] in a human-readable way.
///
/// Return the mnemonic of [`SecAlg`]. If [`SecAlg`] is unknown, then the
/// returned string contains the number of the Algorithm.
///
/// [Section 2.2 of RFC4034] states:
///
/// > The Algorithm field MUST be represented either as an unsigned decimal
/// > integer or as an algorithm mnemonic as specified in Appendix A.1.
///
/// The algorithms are consolidated by [IANA].
///
/// ```
/// # use domain::new::rdata::SecAlg;
/// // Known Security Algorithm with mnemonic.
/// assert_eq!("DSA", format!("{}", SecAlg::DSA_SHA1));
/// // Unknown Security Algorithm.
/// assert_eq!("42", format!("{}", SecAlg::from(42)));
/// ```
///
/// [Section 2.2 of RFC4034]: https://datatracker.ietf.org/doc/html/rfc4034#section-2.2
/// [IANA]: https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1
impl fmt::Display for SecAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "{}", m),
            None => write!(f, "{}", self.code),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::new::rdata::SecAlg;

    #[test]
    fn test_secalg_from() {
        let secalg: SecAlg = 3.into();
        assert_eq!(secalg, SecAlg::DSA_SHA1);

        let number: u8 = secalg.into();
        assert_eq!(number, 3);
    }

    #[test]
    fn test_secalg_from_mnemonic() {
        assert_eq!(SecAlg::from_mnemonic("DSA").unwrap(), SecAlg::DSA_SHA1);
        assert_eq!(
            SecAlg::from_mnemonic("RSASHA1").unwrap(),
            SecAlg::RSA_SHA1
        );
    }
}
