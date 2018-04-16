//! DNSSEC Algorithm Numbers

use std::cmp;
use std::fmt;
use std::hash;
use std::str;


//------------ SecAlg -------------------------------------------------------

/// Security Algorithm Numbers.
///
/// These numbers are used in various security related record types.
///
/// For the currently registered values see the [IANA registration].
///
/// [IANA registration]: http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1].
#[derive(Clone, Copy, Debug)]
pub enum SecAlg {
    /// RSA/MD5
    ///
    /// This algorithm was described in RFC 2537 and since has been
    /// deprecated due to weaknesses of the MD5 hash algorithm by RFC 3110
    /// which suggests to use RSA/SHA1 instead.
    ///
    /// This algorithm may not be used for zone signing but may be used
    /// for transaction security.
    RsaMd5,

    /// Diffie-Hellman
    ///
    /// This algorithm is described in RFC 2539 for storing Diffie-Hellman
    /// (DH) keys in DNS resource records. It can not be used for zone
    /// signing but only for transaction security.
    Dh,

    /// DSA/SHA1
    ///
    /// This algorithm is described in RFC 2536. It may be used both for
    /// zone signing and transaction security.
    Dsa,

    /// RSA/SHA-1
    ///
    /// This algorithm is described in RFC 3110. It may be used both for
    /// zone signing and transaction security. It is mandatory for DNSSEC
    /// implementations.
    RsaSha1,

    /// DSA-NSEC3-SHA1
    ///
    /// This value is an alias for `Dsa` for use within NSEC3 records.
    DsaNsec3Sha1,

    /// RSASHA1-NSEC3-SHA1
    ///
    /// This value is an alias for `RsaSha1` for use within NSEC3 records.
    RsaSha1Nsec3Sha1,

    /// RSA/SHA-256
    ///
    /// This algorithm is described in RFC 5702. It may be used for zone
    /// signing only.
    RsaSha256,

    /// RSA/SHA-512
    ///
    /// This algorithm is described in RFC 5702. It may be used for zone
    /// signing only.
    RsaSha512,

    /// GOST R 34.10-2001
    ///
    /// This algorithm is described in RFC 5933. It may be used for zone
    /// signing only.
    EccGost,

    /// ECDSA Curve P-256 with SHA-256
    ///
    /// This algorithm is described in RFC 6605. It may be used for zone
    /// signing only.
    EcdsaP256Sha256,

    /// ECDSA Curve P-384 with SHA-384
    ///
    /// This algorithm is described in RFC 6605. It may be used for zone
    /// signing only.
    EcdsaP384Sha384,

    /// Reserved for Indirect Keys
    ///
    /// This value is reserved by RFC 4034.
    Indirect,

    /// A private algorithm identified by a domain name.
    ///
    /// This value is defined in RFC 4034.
    PrivateDns,

    /// A private algorithm identified by a ISO OID.
    ///
    /// This value is defined in RFC 4034.
    PrivateOid,

    /// A raw algorithm value given through its integer value.
    Int(u8)
}

impl SecAlg {
    /// Returns the algorithm value for the given integer value.
    pub fn from_int(value: u8) -> SecAlg {
        use self::SecAlg::*;

        match value {
            1 => RsaMd5,
            2 => Dh,
            3 => Dsa,
            5 => RsaSha1,
            6 => DsaNsec3Sha1,
            7 => RsaSha1Nsec3Sha1,
            8 => RsaSha256,
            10 => RsaSha512,
            12 => EccGost,
            13 => EcdsaP256Sha256,
            14 => EcdsaP384Sha384,
            252 => Indirect,
            253 => PrivateDns,
            254 => PrivateOid,
            _ => Int(value)
        }
    }

    /// Returns the integer value for this algorithm value.
    pub fn to_int(self) -> u8 {
        use self::SecAlg::*;

        match self {
            RsaMd5 => 1,
            Dh => 2,
            Dsa => 3,
            RsaSha1 => 5,
            DsaNsec3Sha1 => 6,
            RsaSha1Nsec3Sha1 => 7,
            RsaSha256 => 8,
            RsaSha512 => 10,
            EccGost => 12,
            EcdsaP256Sha256 => 13,
            EcdsaP384Sha384 => 14,
            Indirect => 252,
            PrivateDns => 253,
            PrivateOid => 254,
            Int(value) => value
        }
    }
}


//--- From

impl From<u8> for SecAlg {
    fn from(value: u8) -> SecAlg {
        SecAlg::from_int(value)
    }
}

impl From<SecAlg> for u8 {
    fn from(value: SecAlg) -> u8 {
        value.to_int()
    }
}


//--- FromStr

impl str::FromStr for SecAlg {
    type Err = FromStrError;

    /// Returns the algorithm value for the given string.
    ///
    /// Recognized are the mnemonics equivalent to the algorithm number not
    /// regarding case as well as decimal integer numbers.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::SecAlg::*;

        if s.eq_ignore_ascii_case("RSAMD5") { Ok(RsaMd5) }
        else if s.eq_ignore_ascii_case("DH") { Ok(Dh) }
        else if s.eq_ignore_ascii_case("DSA") { Ok(Dsa) }
        else if s.eq_ignore_ascii_case("RSASHA1") { Ok(RsaSha1) }
        else if s.eq_ignore_ascii_case("DSA-NSEC3-SHA1") { Ok(DsaNsec3Sha1) }
        else if s.eq_ignore_ascii_case("RSASHA1-NSEC3-SHA1") {
            Ok(RsaSha1Nsec3Sha1)
        }
        else if s.eq_ignore_ascii_case("RSASHA256") { Ok(RsaSha256) }
        else if s.eq_ignore_ascii_case("RSASHA512") { Ok(RsaSha512) }
        else if s.eq_ignore_ascii_case("ECC-GOST") { Ok(EccGost) }
        else if s.eq_ignore_ascii_case("ECDSAP256SHA256") {
            Ok(EcdsaP256Sha256)
        }
        else if s.eq_ignore_ascii_case("ECDSAP384SHA384") {
            Ok(EcdsaP384Sha384)
        }
        else if s.eq_ignore_ascii_case("INDIRECT") { Ok(Indirect) }
        else if s.eq_ignore_ascii_case("PRIVATEDNS") { Ok(PrivateDns) }
        else if s.eq_ignore_ascii_case("PRIVATEOID") { Ok(PrivateOid) }
        else {
            match u8::from_str(s) {
                Ok(value) => Ok(SecAlg::from_int(value)),
                Err(..) => Err(FromStrError)
            }
        }
    }
}


//--- Display

impl fmt::Display for SecAlg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SecAlg::*;

        match *self {
            RsaMd5 => "RSAMD5".fmt(f),
            Dh => "DH".fmt(f),
            Dsa => "DSA".fmt(f),
            RsaSha1 => "RSASHA1".fmt(f),
            DsaNsec3Sha1 => "DSA-NSEC3-SHA1".fmt(f),
            RsaSha1Nsec3Sha1 => "RSASHA1-NSEC3-SHA1".fmt(f),
            RsaSha256 => "RSASHA256".fmt(f),
            RsaSha512 => "RSASHA512".fmt(f),
            EccGost => "ECC-GOST".fmt(f),
            EcdsaP256Sha256 => "ECDSAP256SHA256".fmt(f),
            EcdsaP384Sha384 => "ECDSAP384SHA384".fmt(f),
            Indirect => "INDIRECT".fmt(f),
            PrivateDns => "PRVIATEDNS".fmt(f),
            PrivateOid => "PRIVATEOID".fmt(f),
            Int(value) => {
                match SecAlg::from_int(value) {
                    Int(value) => value.fmt(f),
                    value => value.fmt(f)
                }
            }
        }
    }
}
 

//--- PartialEq and Eq

impl PartialEq for SecAlg {
    fn eq(&self, other: &SecAlg) -> bool {
        self.to_int() == other.to_int()
    }
}

impl PartialEq<u8> for SecAlg {
    fn eq(&self, other: &u8) -> bool {
        self.to_int() == *other
    }
}

impl PartialEq<SecAlg> for u8 {
    fn eq(&self, other: &SecAlg) -> bool {
        *self == other.to_int()
    }
}

impl Eq for SecAlg { }


//--- PartialOrd and Ord

impl PartialOrd for SecAlg {
    fn partial_cmp(&self, other: &SecAlg) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(&other.to_int())
    }
}

impl PartialOrd<u8> for SecAlg {
    fn partial_cmp(&self, other: &u8) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(other)
    }
}

impl PartialOrd<SecAlg> for u8 {
    fn partial_cmp(&self, other: &SecAlg) -> Option<cmp::Ordering> {
        self.partial_cmp(&other.to_int())
    }
}

impl Ord for SecAlg {
    fn cmp(&self, other: &SecAlg) -> cmp::Ordering {
        self.to_int().cmp(&other.to_int())
    }
}


//--- Hash

impl hash::Hash for SecAlg {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.to_int().hash(state)
    }
}


from_str_error!("unknown algorithm");
