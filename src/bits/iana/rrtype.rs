//! Resource Record (RR) TYPEs
//!

use std::cmp;
use std::convert;
use std::fmt;
use std::hash;
use std::str;
use super::super::error::{FromStrError, FromStrResult};


/// Resource Record Types.
///
/// Each resource records has a 16 bit type value indicating what kind of
/// information is represented by the record. Normal query includes the type
/// of record information is requested for. A few aditional types, called
/// query types, are defined as well and can only be used in questions. This
/// type represents both these types.
///
/// Record types are defined in RFC 1035. The registry of currently assigned
/// values can be found at
/// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
#[derive(Clone, Copy, Debug)]
pub enum RRType {
    /// A host address.
    A,

    /// An authoritative name server.
    NS,

    /// A mail destination.
    ///
    /// (Obsolete – use MX)
    MD,

    /// A mail forwarder.
    ///
    /// (Obsolete – use MX)
    MF,

    /// The canonical name for an alias
    CNAME,

    /// Marks the start of a zone of authority.
    SOA,

    /// A mailbox domain name.
    ///
    /// (Experimental.)
    MB,

    /// A mail group member
    ///
    /// (Experimental.)
    MG,

    /// A mail rename domain name.
    ///
    /// (Experimental.)
    MR,
    
    /// A null resource record.
    ///
    /// (Experimental.)
    NULL,

    /// A well known service description.
    WKS,

    /// A domain name pointer.
    PTR,

    /// Host information.
    HINFO,

    /// Mailbox or mail list information.
    MINFO,

    /// Mail exchange.
    MX,

    /// Text strings.
    TXT,
    
    /// For Responsible Person.
    ///
    /// See RFC 1183
    RP,

    /// For AFS Data Base location.
    ///
    /// See RFC 1183 and RFC 5864.
    AFSDB,

    /// For X.25 PSDN address.
    ///
    /// See RFC 1183.
    X25,

    /// For ISDN address.
    ///
    /// See RFC 1183.
    ISDN,

    /// For Route Through.
    ///
    /// See RFC 1183
    RT,

    /// For SNAP address, NSAP style A record.
    ///
    /// See RFC 1706.
    NSAP,
    
    /// For domain name pointer, NSAP style.
    ///
    /// See RFC 1348, RFC 1637, RFC 1706.
    NSAPPTR,

    /// For security signature.
    SIG,

    /// For security key.
    KEY,

    /// X.400 mail mapping information.
    ///
    /// See RFC 2163.
    PX,

    /// Geographical position.
    ///
    /// See RFC 1712
    GPOS,
    
    /// IPv6 address.
    ///
    /// See RFC 3596.
    AAAA,

    /// Location information.
    ///
    /// See RFC 1876.
    LOC,

    /// Next domain.
    ///
    /// (Obsolete.)
    ///
    /// See RFC 3755 and RFC 2535.
    NXT,

    /// Endpoint identifier.
    EID,

    /// Nimrod locator.
    NIMLOC,

    /// Server selection.
    ///
    /// See RFC 2782.
    SRV,

    /// ATM address.
    ATMA,

    /// Naming authority pointer.
    ///
    /// See RFC 2915, RFC 2168, and RFC 3403.
    NAPTR,

    /// Key exchanger.
    ///
    /// See RFC 2230.
    KX,

    /// CERT
    ///
    /// See RFC 4398.
    CERT,

    /// A6.
    ///
    /// (Obsolete – use AAAA.)
    ///
    /// See RFC 3226, RFC 2874, and RFC 6563.
    A6,

    /// DNAME.
    ///
    /// See RFC 6672.
    DNAME,

    /// SINK.
    SINK,

    /// OPT.
    ///
    /// See RFC 6891 and RFC 3225.
    OPT,

    /// APL.
    ///
    /// See RFC 3123.
    APL,

    /// Delegation signer.
    ///
    /// See RFC 4034 and RFC 3658.
    DS,

    /// SSH key fingerprint.
    ///
    /// See RFC 4255.
    SSHFP,

    /// IPSECKEY
    ///
    /// See RFC 4255.
    IPSECKEY,

    /// RRSIG.
    ///
    /// See RFC 4034 and RFC 3755.
    RRSIG,

    /// NSEC.
    ///
    /// See RFC 4034 and RFC 3755.
    NSEC,

    /// DNSKEY.
    ///
    /// See RFC 4034 and RFC 3755.
    DNSKEY,

    /// DHCID.
    ///
    /// See RFC 4701.
    DHCID,

    /// NSEC3
    ///
    /// See RFC 5155.
    NSEC3,

    /// NSEC3PARAM.
    ///
    /// See RFC 5155.
    NSEC3PARAM,
    
    /// TLSA.
    ///
    /// See RFC 6698.
    TLSA,

    /// S/MIME cert association.
    ///
    /// See draft-ietf-dane-smime.
    SMIMEA,

    /// Host Identity Protocol.
    ///
    /// See RFC 5205.
    HIP,

    /// NINFO.
    NINFO,

    /// RKEY.
    RKEY,

    /// Trust Anchor Link
    TALINK,

    /// Child DS.
    ///
    /// See RFC 7344.
    CDS,

    /// DNSKEY(s) the child wants reflected in DS.
    ///
    /// See RFC 7344.
    CDNSKEY,
    
    /// OpenPGP key.
    ///
    /// See draft-ietf-dane-openpgpkey.
    OPENPGPKEY,

    /// Child-to-parent synchronization.
    ///
    /// See RFC 7477.
    CSYNC,

    /// SPF.
    ///
    /// RFC 7208.
    SPF,

    /// UINFO.
    ///
    /// IANA-Reserved.
    UINFO,
    
    /// UID.
    ///
    /// IANA-Reserved.
    UID,

    /// GID.
    ///
    /// IANA-Reserved.
    GID,

    /// UNSPEC.
    ///
    /// IANA-Reserved.
    UNSPEC,

    /// NID.
    ///
    /// See RFC 6742.
    NID,

    /// L32.
    ///
    /// See RFC 6742.
    L32,

    /// L64.
    ///
    /// See RFC 6742.
    L64,

    /// LP.
    ///
    /// See RFC 6742.
    LP,

    /// An EUI-48 address.
    ///
    /// See RFC 7043.
    EUI48,

    /// An EUI-64 address.
    ///
    /// See RFC 7043.
    EUI64,
    
    /// Transaction key.
    ///
    /// See RFC 2930.
    TKEY,
    
    /// Transaction signature.
    ///
    /// See RFC 2845.
    TSIG,

    /// Incremental transfer.
    ///
    /// See RFC 1995.
    IXFR,
    
    /// Transfer of entire zone.
    ///
    /// See RFC 1035 and RFC 5936.
    AXFR,

    /// Mailbox-related RRs (MB, MG, or MR).
    MAILB,

    /// Mail agent RRS.
    ///
    /// (Obsolete – see MX.)
    MAILA,

    /// A request for all records the server/cache has available.
    ///
    /// See RFC 1035 and RFC 6895.
    ANY,

    /// URI.
    ///
    /// See RFC 7553.
    URI,

    /// Certification Authority Restriction.
    ///
    /// See RFC 6844.
    CAA,

    /// Application visibility and control.
    AVC,

    /// DNSSEC trust authorities.
    TA,

    /// DNSSEC lookaside validation.
    ///
    /// See RFC 4431
    DLV,

    /// A raw integer RR type value.
    Int(u16)
}

impl RRType {
    /// Creates a type value from an integer value.
    pub fn from_int(value: u16) -> RRType {
        use self::RRType::*;

        match value {
            1 => A,
            2 => NS,
            3 => MD,
            4 => MF,
            5 => CNAME,
            6 => SOA,
            7 => MB,
            8 => MG,
            9 => MR,
            10 => NULL,
            11 => WKS,
            12 => PTR,
            13 => HINFO,
            14 => MINFO,
            15 => MX,
            16 => TXT,
            17 => RP,
            18 => AFSDB,
            19 => X25,
            20 => ISDN,
            21 => RT,
            22 => NSAP,
            23 => NSAPPTR,
            24 => SIG,
            25 => KEY,
            26 => PX,
            27 => GPOS,
            28 => AAAA,
            29 => LOC,
            30 => NXT,
            31 => EID,
            32 => NIMLOC,
            33 => SRV,
            34 => ATMA,
            35 => NAPTR,
            36 => KX,
            37 => CERT,
            38 => A6,
            39 => DNAME,
            40 => SINK,
            41 => OPT,
            42 => APL,
            43 => DS,
            44 => SSHFP,
            45 => IPSECKEY,
            46 => RRSIG,
            47 => NSEC,
            48 => DNSKEY,
            49 => DHCID,
            50 => NSEC3,
            51 => NSEC3PARAM,
            52 => TLSA,
            53 => SMIMEA,
            // 54
            55 => HIP,
            56 => NINFO,
            57 => RKEY,
            58 => TALINK,
            59 => CDS,
            60 => CDNSKEY,
            61 => OPENPGPKEY,
            62 => CSYNC,
            // 63-98
            99 => SPF,
            100 => UINFO,
            101 => UID,
            102 => GID,
            103 => UNSPEC,
            104 => NID,
            105 => L32,
            106 => L64,
            107 => LP,
            108 => EUI48,
            109 => EUI64,
            // 110-248
            249 => TKEY,
            250 => TSIG,
            251 => IXFR,
            252 => AXFR,
            253 => MAILB,
            254 => MAILA,
            255 => ANY,
            256 => URI,
            257 => CAA,
            258 => AVC,
            // 259-32767
            32768 => TA,
            32769 => DLV,
            _ => Int(value)
        }
    }

    /// Returns an integer value for this type value.
    pub fn to_int(self) -> u16 {
        use self::RRType::*;

        match self {
            A => 1,
            NS => 2,
            MD => 3,
            MF => 4,
            CNAME => 5,
            SOA => 6,
            MB => 7,
            MG => 8,
            MR => 9,
            NULL => 10,
            WKS => 11,
            PTR => 12,
            HINFO => 13,
            MINFO => 14,
            MX => 15,
            TXT => 16,
            RP => 17,
            AFSDB => 18,
            X25 => 19,
            ISDN => 20,
            RT => 21,
            NSAP => 22,
            NSAPPTR => 23,
            SIG => 24,
            KEY => 25,
            PX => 26,
            GPOS => 27,
            AAAA => 28,
            LOC => 29,
            NXT => 30,
            EID => 31,
            NIMLOC => 32,
            SRV => 33,
            ATMA => 34,
            NAPTR => 35,
            KX => 36,
            CERT => 37,
            A6 => 38,
            DNAME => 39,
            SINK => 40,
            OPT => 41,
            APL => 42,
            DS => 43,
            SSHFP => 44,
            IPSECKEY => 45,
            RRSIG => 46,
            NSEC => 47,
            DNSKEY => 48,
            DHCID => 49,
            NSEC3 => 50,
            NSEC3PARAM => 51,
            TLSA => 52,
            SMIMEA => 53,
            HIP => 55,
            NINFO => 56,
            RKEY => 57,
            TALINK => 58,
            CDS => 59,
            CDNSKEY => 60,
            OPENPGPKEY => 61,
            CSYNC => 62,
            SPF => 99,
            UINFO => 100,
            UID => 101,
            GID => 102,
            UNSPEC => 103,
            NID => 104,
            L32 => 105,
            L64 => 106,
            LP => 107,
            EUI48 => 108,
            EUI64 => 109,
            TKEY => 249,
            TSIG => 250,
            IXFR => 251,
            AXFR => 252,
            MAILB => 253,
            MAILA => 254,
            ANY => 255,
            URI => 256,
            CAA => 257,
            AVC => 258,
            TA => 32768,
            DLV => 32769,
            Int(value) => value
        }
    }
}


//--- From

impl convert::From<u16> for RRType {
    fn from(value: u16) -> RRType {
        RRType::from_int(value)
    }
}

impl convert::From<RRType> for u16 {
    fn from(value: RRType) -> u16 {
        value.to_int()
    }
}


//--- FromStr

impl str::FromStr for RRType {
    type Err = FromStrError;

    /// Creates a type value from a string.
    ///
    /// Recognises the mnemonics (ie., the ‘TYPE’ field in the IANA
    /// registry) as well as the generic type value defined in RFC 3597,
    /// ie., the string `TYPE` followed by the decimal type value.
    fn from_str(s: &str) -> FromStrResult<Self> {
        use std::ascii::AsciiExt;
        use self::RRType::*;

        if s.eq_ignore_ascii_case("A") { Ok(A) }
        else if s.eq_ignore_ascii_case("NS") { Ok(NS) }
        else if s.eq_ignore_ascii_case("MD") { Ok(MD) }
        else if s.eq_ignore_ascii_case("MF") { Ok(MF) }
        else if s.eq_ignore_ascii_case("CNAME") { Ok(CNAME) }
        else if s.eq_ignore_ascii_case("SOA") { Ok(SOA) }
        else if s.eq_ignore_ascii_case("MB") { Ok(MB) }
        else if s.eq_ignore_ascii_case("MG") { Ok(MG) }
        else if s.eq_ignore_ascii_case("MR") { Ok(MR) }
        else if s.eq_ignore_ascii_case("NULL") { Ok(NULL) }
        else if s.eq_ignore_ascii_case("WKS") { Ok(WKS) }
        else if s.eq_ignore_ascii_case("PTR") { Ok(PTR) }
        else if s.eq_ignore_ascii_case("HINFO") { Ok(HINFO) }
        else if s.eq_ignore_ascii_case("MINFO") { Ok(MINFO) }
        else if s.eq_ignore_ascii_case("MX") { Ok(MX) }
        else if s.eq_ignore_ascii_case("TXT") { Ok(TXT) }
        else if s.eq_ignore_ascii_case("RP") { Ok(RP) }
        else if s.eq_ignore_ascii_case("AFSDB") { Ok(AFSDB) }
        else if s.eq_ignore_ascii_case("X25") { Ok(X25) }
        else if s.eq_ignore_ascii_case("ISDN") { Ok(ISDN) }
        else if s.eq_ignore_ascii_case("RT") { Ok(RT) }
        else if s.eq_ignore_ascii_case("NSAP") { Ok(NSAP) }
        else if s.eq_ignore_ascii_case("NSAP-PTR") { Ok(NSAPPTR) }
        else if s.eq_ignore_ascii_case("SIG") { Ok(SIG) }
        else if s.eq_ignore_ascii_case("KEY") { Ok(KEY) }
        else if s.eq_ignore_ascii_case("PX") { Ok(PX) }
        else if s.eq_ignore_ascii_case("GPOS") { Ok(GPOS) }
        else if s.eq_ignore_ascii_case("AAAA") { Ok(AAAA) }
        else if s.eq_ignore_ascii_case("LOC") { Ok(LOC) }
        else if s.eq_ignore_ascii_case("NXT") { Ok(NXT) }
        else if s.eq_ignore_ascii_case("EID") { Ok(EID) }
        else if s.eq_ignore_ascii_case("NIMLOC") { Ok(NIMLOC) }
        else if s.eq_ignore_ascii_case("SRV") { Ok(SRV) }
        else if s.eq_ignore_ascii_case("ATMA") { Ok(ATMA) }
        else if s.eq_ignore_ascii_case("NAPTR") { Ok(NAPTR) }
        else if s.eq_ignore_ascii_case("KX") { Ok(KX) }
        else if s.eq_ignore_ascii_case("CERT") { Ok(CERT) }
        else if s.eq_ignore_ascii_case("A6") { Ok(A6) }
        else if s.eq_ignore_ascii_case("DNAME") { Ok(DNAME) }
        else if s.eq_ignore_ascii_case("SINK") { Ok(SINK) }
        else if s.eq_ignore_ascii_case("OPT") { Ok(OPT) }
        else if s.eq_ignore_ascii_case("APL") { Ok(APL) }
        else if s.eq_ignore_ascii_case("DS") { Ok(DS) }
        else if s.eq_ignore_ascii_case("SSHFP") { Ok(SSHFP) }
        else if s.eq_ignore_ascii_case("IPSECKEY") { Ok(IPSECKEY) }
        else if s.eq_ignore_ascii_case("RRSIG") { Ok(RRSIG) }
        else if s.eq_ignore_ascii_case("NSEC") { Ok(NSEC) }
        else if s.eq_ignore_ascii_case("DNSKEY") { Ok(DNSKEY) }
        else if s.eq_ignore_ascii_case("DHCID") { Ok(DHCID) }
        else if s.eq_ignore_ascii_case("NSEC3") { Ok(NSEC3) }
        else if s.eq_ignore_ascii_case("NSEC3PARAM") { Ok(NSEC3PARAM) }
        else if s.eq_ignore_ascii_case("TLSA") { Ok(TLSA) }
        else if s.eq_ignore_ascii_case("SMIMEA") { Ok(SMIMEA) }
        else if s.eq_ignore_ascii_case("HIP") { Ok(HIP) }
        else if s.eq_ignore_ascii_case("NINFO") { Ok(NINFO) }
        else if s.eq_ignore_ascii_case("RKEY") { Ok(RKEY) }
        else if s.eq_ignore_ascii_case("TALINK") { Ok(TALINK) }
        else if s.eq_ignore_ascii_case("CDS") { Ok(CDS) }
        else if s.eq_ignore_ascii_case("CDNSKEY") { Ok(CDNSKEY) }
        else if s.eq_ignore_ascii_case("OPENPGPKEY") { Ok(OPENPGPKEY) }
        else if s.eq_ignore_ascii_case("CSYNC") { Ok(CSYNC) }
        else if s.eq_ignore_ascii_case("SPF") { Ok(SPF) }
        else if s.eq_ignore_ascii_case("UINFO") { Ok(UINFO) }
        else if s.eq_ignore_ascii_case("UID") { Ok(UID) }
        else if s.eq_ignore_ascii_case("GID") { Ok(GID) }
        else if s.eq_ignore_ascii_case("UNSPEC") { Ok(UNSPEC) }
        else if s.eq_ignore_ascii_case("NID") { Ok(NID) }
        else if s.eq_ignore_ascii_case("L32") { Ok(L32) }
        else if s.eq_ignore_ascii_case("L64") { Ok(L64) }
        else if s.eq_ignore_ascii_case("LP") { Ok(LP) }
        else if s.eq_ignore_ascii_case("EUI48") { Ok(EUI48) }
        else if s.eq_ignore_ascii_case("EUI64") { Ok(EUI64) }
        else if s.eq_ignore_ascii_case("TKEY") { Ok(TKEY) }
        else if s.eq_ignore_ascii_case("TSIG") { Ok(TSIG) }
        else if s.eq_ignore_ascii_case("IXFR") { Ok(IXFR) }
        else if s.eq_ignore_ascii_case("AXFR") { Ok(AXFR) }
        else if s.eq_ignore_ascii_case("MAILB") { Ok(MAILB) }
        else if s.eq_ignore_ascii_case("MAILA") { Ok(MAILA) }
        else if s.eq_ignore_ascii_case("ANY") { Ok(ANY) }
        else if s.eq_ignore_ascii_case("URI") { Ok(URI) }
        else if s.eq_ignore_ascii_case("CAA") { Ok(CAA) }
        else if s.eq_ignore_ascii_case("AVC") { Ok(AVC) }
        else if s.eq_ignore_ascii_case("TA") { Ok(TA) }
        else if s.eq_ignore_ascii_case("DLV") { Ok(DLV) }
        else {
            if let Some((n, _)) = s.char_indices().nth(4) {
                let (l, r) = s.split_at(n);
                if l.eq_ignore_ascii_case("TYPE") {
                    let value = match u16::from_str_radix(r, 10) {
                        Ok(x) => x,
                        Err(..) => return Err(FromStrError::UnknownType)
                    };
                    Ok(Int(value))
                }
                else {
                    Err(FromStrError::UnknownType)
                }
            }
            else {
                Err(FromStrError::UnknownType)
            }
        }
    }
}


//--- Display

impl fmt::Display for RRType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::RRType::*;

        match *self {
            A => "A".fmt(f),
            NS => "NS".fmt(f),
            MD => "MD".fmt(f),
            MF => "MF".fmt(f),
            CNAME => "CNAME".fmt(f),
            SOA => "SOA".fmt(f),
            MB => "MB".fmt(f),
            MG => "MG".fmt(f),
            MR => "MR".fmt(f),
            NULL => "NULL".fmt(f),
            WKS => "WKS".fmt(f),
            PTR => "PTR".fmt(f),
            HINFO => "HINFO".fmt(f),
            MINFO => "MINFO".fmt(f),
            MX => "MX".fmt(f),
            TXT => "TXT".fmt(f),
            RP => "RP".fmt(f),
            AFSDB => "AFSDB".fmt(f),
            X25 => "X25".fmt(f),
            ISDN => "ISDN".fmt(f),
            RT => "RT".fmt(f),
            NSAP => "NSAP".fmt(f),
            NSAPPTR => "NSAP-PTR".fmt(f),
            SIG => "SIG".fmt(f),
            KEY => "KEY".fmt(f),
            PX => "PX".fmt(f),
            GPOS => "GPOS".fmt(f),
            AAAA => "AAAA".fmt(f),
            LOC => "LOC".fmt(f),
            NXT => "NXT".fmt(f),
            EID => "EID".fmt(f),
            NIMLOC => "NIMLOC".fmt(f),
            SRV => "SRV".fmt(f),
            ATMA => "ATMA".fmt(f),
            NAPTR => "NAPTR".fmt(f),
            KX => "KX".fmt(f),
            CERT => "CERT".fmt(f),
            A6 => "A6".fmt(f),
            DNAME => "DNAME".fmt(f),
            SINK => "SINK".fmt(f),
            OPT => "OPT".fmt(f),
            APL => "APL".fmt(f),
            DS => "DS".fmt(f),
            SSHFP => "SSHFP".fmt(f),
            IPSECKEY => "IPSECKEY".fmt(f),
            RRSIG => "RRSIG".fmt(f),
            NSEC => "NSEC".fmt(f),
            DNSKEY => "DNSKEY".fmt(f),
            DHCID => "DHCID".fmt(f),
            NSEC3 => "NSEC3".fmt(f),
            NSEC3PARAM => "NSEC3PARAM".fmt(f),
            TLSA => "TLSA".fmt(f),
            SMIMEA => "SMIMEA".fmt(f),
            HIP => "HIP".fmt(f),
            NINFO => "NINFO".fmt(f),
            RKEY => "RKEY".fmt(f),
            TALINK => "TALINK".fmt(f),
            CDS => "CDS".fmt(f),
            CDNSKEY => "CDNSKEY".fmt(f),
            OPENPGPKEY => "OPENPGPKEY".fmt(f),
            CSYNC => "CSYNC".fmt(f),
            SPF => "SPF".fmt(f),
            UINFO => "UINFO".fmt(f),
            UID => "UID".fmt(f),
            GID => "GID".fmt(f),
            UNSPEC => "UNSPEC".fmt(f),
            NID => "NID".fmt(f),
            L32 => "L32".fmt(f),
            L64 => "L64".fmt(f),
            LP => "LP".fmt(f),
            EUI48 => "EUI48".fmt(f),
            EUI64 => "EUI64".fmt(f),
            TKEY => "TKEY".fmt(f),
            TSIG => "TSIG".fmt(f),
            IXFR => "IXFR".fmt(f),
            AXFR => "AXFR".fmt(f),
            MAILB => "MAILB".fmt(f),
            MAILA => "MAILA".fmt(f),
            ANY => "ANY".fmt(f),
            URI => "URI".fmt(f),
            CAA => "CAA".fmt(f),
            AVC => "AVC".fmt(f),
            TA => "TA".fmt(f),
            DLV => "DLV".fmt(f),
            Int(value) => {
                match RRType::from_int(value) {
                    Int(value) => write!(f, "TYPE{}", value),
                    value @ _ => value.fmt(f)
                }
            }
        }
    }
}


//--- PartialEq and Eq

impl PartialEq for RRType {
    fn eq(&self, other: &Self) -> bool {
        self.to_int() == other.to_int()
    }
}

impl PartialEq<u16> for RRType {
    fn eq(&self, other: &u16) -> bool {
        self.to_int() == *other
    }
}

impl PartialEq<RRType> for u16 {
    fn eq(&self, other: &RRType) -> bool {
        *self == other.to_int()
    }
}

impl Eq for RRType { }


//--- PartialOrd and Ord

impl PartialOrd for RRType {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(&other.to_int())
    }
}

impl PartialOrd<u16> for RRType {
    fn partial_cmp(&self, other: &u16) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(other)
    }
}

impl PartialOrd<RRType> for u16 {
    fn partial_cmp(&self, other: &RRType) -> Option<cmp::Ordering> {
        self.partial_cmp(&other.to_int())
    }
}

impl Ord for RRType {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.to_int().cmp(&other.to_int())
    }
}


//--- Hash

impl hash::Hash for RRType {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.to_int().hash(state)
    }
}

