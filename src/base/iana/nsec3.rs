//! NSEC3 hash algorithms.

//------------ Nsec3HashAlgorithm --------------------------------------------

use crate::base::iana::macros::FromStrError;
use crate::base::iana::macros::IanaEnum;

iana_enum! {
    /// NSEC3 hash algorithm numbers.
    ///
    /// This type selects the algorithm used to hash domain names for use with
    /// the [NSEC3].
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2008-03-05.
    ///
    /// [NSEC3]: ../../../rdata/rfc5155/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml#dnssec-nsec3-parameters-3
    =>
    Nsec3HashAlgorithm, u8;
    display_integer,
    parse_from_mnemonic_or_integer,
    serialize_to_integer,
    deserialize_from_integer,
    "";

    /// Specifies that the SHA-1 hash function is used.
    (SHA1 => 1, "SHA-1")
}

int_enum_zonefile_fmt_decimal!(Nsec3HashAlgorithm, "hash algorithm");

