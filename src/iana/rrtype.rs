//! Resource Record (RR) TYPEs
//!

use std::cmp;
use std::convert;
use std::fmt;
use std::hash;
use std::str;
use bits::error::{FromStrError, FromStrResult};


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
/// 
/// In order to avoid confusion over capitalization, the mnemonics are
/// treated as single acronyms and therefore all variant names are spelled
/// with an initial capital letter in accordance with Rust naming guidelines.
#[derive(Clone, Copy, Debug)]
pub enum RRType {
    /// A host address.
    A,

    /// An authoritative name server.
    Ns,

    /// A mail destination.
    ///
    /// (Obsolete – use MX)
    Md,

    /// A mail forwarder.
    ///
    /// (Obsolete – use MX)
    Mf,

    /// The canonical name for an alias
    Cname,

    /// Marks the start of a zone of authority.
    Soa,

    /// A mailbox domain name.
    ///
    /// (Experimental.)
    Mb,

    /// A mail group member
    ///
    /// (Experimental.)
    Mg,

    /// A mail rename domain name.
    ///
    /// (Experimental.)
    Mr,
    
    /// A null resource record.
    ///
    /// (Experimental.)
    Null,

    /// A well known service description.
    Wks,

    /// A domain name pointer.
    Ptr,

    /// Host information.
    Hinfo,

    /// Mailbox or mail list information.
    Minfo,

    /// Mail exchange.
    Mx,

    /// Text strings.
    Txt,
    
    /// For Responsible Person.
    ///
    /// See RFC 1183
    Rp,

    /// For AFS Data Base location.
    ///
    /// See RFC 1183 and RFC 5864.
    Afsdb,

    /// For X.25 PSDN address.
    ///
    /// See RFC 1183.
    X25,

    /// For ISDN address.
    ///
    /// See RFC 1183.
    Isdn,

    /// For Route Through.
    ///
    /// See RFC 1183
    Rt,

    /// For SNAP address, NSAP style A record.
    ///
    /// See RFC 1706.
    Nsap,
    
    /// For domain name pointer, NSAP style.
    ///
    /// See RFC 1348, RFC 1637, RFC 1706.
    Nsapptr,

    /// For security signature.
    Sig,

    /// For security key.
    Key,

    /// X.400 mail mapping information.
    ///
    /// See RFC 2163.
    Px,

    /// Geographical position.
    ///
    /// See RFC 1712
    Gpos,
    
    /// IPv6 address.
    ///
    /// See RFC 3596.
    Aaaa,

    /// Location information.
    ///
    /// See RFC 1876.
    Loc,

    /// Next domain.
    ///
    /// (Obsolete.)
    ///
    /// See RFC 3755 and RFC 2535.
    Nxt,

    /// Endpoint identifier.
    Eid,

    /// Nimrod locator.
    Nimloc,

    /// Server selection.
    ///
    /// See RFC 2782.
    Srv,

    /// ATM address.
    Atma,

    /// Naming authority pointer.
    ///
    /// See RFC 2915, RFC 2168, and RFC 3403.
    Naptr,

    /// Key exchanger.
    ///
    /// See RFC 2230.
    Kx,

    /// CERT
    ///
    /// See RFC 4398.
    Cert,

    /// A6.
    ///
    /// (Obsolete – use AAAA.)
    ///
    /// See RFC 3226, RFC 2874, and RFC 6563.
    A6,

    /// DNAME.
    ///
    /// See RFC 6672.
    Dname,

    /// SINK.
    Sink,

    /// OPT.
    ///
    /// See RFC 6891 and RFC 3225.
    Opt,

    /// APL.
    ///
    /// See RFC 3123.
    Apl,

    /// Delegation signer.
    ///
    /// See RFC 4034 and RFC 3658.
    Ds,

    /// SSH key fingerprint.
    ///
    /// See RFC 4255.
    Sshfp,

    /// IPSECKEY
    ///
    /// See RFC 4255.
    Ipseckey,

    /// RRSIG.
    ///
    /// See RFC 4034 and RFC 3755.
    Rrsig,

    /// NSEC.
    ///
    /// See RFC 4034 and RFC 3755.
    Nsec,

    /// DNSKEY.
    ///
    /// See RFC 4034 and RFC 3755.
    Dnskey,

    /// DHCID.
    ///
    /// See RFC 4701.
    Dhcid,

    /// NSEC3
    ///
    /// See RFC 5155.
    Nsec3,

    /// NSEC3PARAM.
    ///
    /// See RFC 5155.
    Nsec3param,
    
    /// TLSA.
    ///
    /// See RFC 6698.
    Tlsa,

    /// S/MIME cert association.
    ///
    /// See draft-ietf-dane-smime.
    Smimea,

    /// Host Identity Protocol.
    ///
    /// See RFC 5205.
    Hip,

    /// NINFO.
    Ninfo,

    /// RKEY.
    Rkey,

    /// Trust Anchor Link
    Talink,

    /// Child DS.
    ///
    /// See RFC 7344.
    Cds,

    /// DNSKEY(s) the child wants reflected in DS.
    ///
    /// See RFC 7344.
    Cdnskey,
    
    /// OpenPGP key.
    ///
    /// See draft-ietf-dane-openpgpkey.
    Openpgpkey,

    /// Child-to-parent synchronization.
    ///
    /// See RFC 7477.
    Csync,

    /// SPF.
    ///
    /// RFC 7208.
    Spf,

    /// UINFO.
    ///
    /// IANA-Reserved.
    Uinfo,
    
    /// UID.
    ///
    /// IANA-Reserved.
    Uid,

    /// GID.
    ///
    /// IANA-Reserved.
    Gid,

    /// UNSPEC.
    ///
    /// IANA-Reserved.
    Unspec,

    /// NID.
    ///
    /// See RFC 6742.
    Nid,

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
    Lp,

    /// An EUI-48 address.
    ///
    /// See RFC 7043.
    Eui48,

    /// An EUI-64 address.
    ///
    /// See RFC 7043.
    Eui64,
    
    /// Transaction key.
    ///
    /// See RFC 2930.
    Tkey,
    
    /// Transaction signature.
    ///
    /// See RFC 2845.
    Tsig,

    /// Incremental transfer.
    ///
    /// See RFC 1995.
    Ixfr,
    
    /// Transfer of entire zone.
    ///
    /// See RFC 1035 and RFC 5936.
    Axfr,

    /// Mailbox-related RRs (MB, MG, or MR).
    Mailb,

    /// Mail agent RRS.
    ///
    /// (Obsolete – see MX.)
    Maila,

    /// A request for all records the server/cache has available.
    ///
    /// See RFC 1035 and RFC 6895.
    Any,

    /// URI.
    ///
    /// See RFC 7553.
    Uri,

    /// Certification Authority Restriction.
    ///
    /// See RFC 6844.
    Caa,

    /// Application visibility and control.
    Avc,

    /// DNSSEC trust authorities.
    Ta,

    /// DNSSEC lookaside validation.
    ///
    /// See RFC 4431
    Dlv,

    /// A raw integer RR type value.
    Int(u16)
}

impl RRType {
    /// Creates a type value from an integer value.
    pub fn from_int(value: u16) -> RRType {
        use self::RRType::*;

        match value {
            1 => A,
            2 => Ns,
            3 => Md,
            4 => Mf,
            5 => Cname,
            6 => Soa,
            7 => Mb,
            8 => Mg,
            9 => Mr,
            10 => Null,
            11 => Wks,
            12 => Ptr,
            13 => Hinfo,
            14 => Minfo,
            15 => Mx,
            16 => Txt,
            17 => Rp,
            18 => Afsdb,
            19 => X25,
            20 => Isdn,
            21 => Rt,
            22 => Nsap,
            23 => Nsapptr,
            24 => Sig,
            25 => Key,
            26 => Px,
            27 => Gpos,
            28 => Aaaa,
            29 => Loc,
            30 => Nxt,
            31 => Eid,
            32 => Nimloc,
            33 => Srv,
            34 => Atma,
            35 => Naptr,
            36 => Kx,
            37 => Cert,
            38 => A6,
            39 => Dname,
            40 => Sink,
            41 => Opt,
            42 => Apl,
            43 => Ds,
            44 => Sshfp,
            45 => Ipseckey,
            46 => Rrsig,
            47 => Nsec,
            48 => Dnskey,
            49 => Dhcid,
            50 => Nsec3,
            51 => Nsec3param,
            52 => Tlsa,
            53 => Smimea,
            // 54
            55 => Hip,
            56 => Ninfo,
            57 => Rkey,
            58 => Talink,
            59 => Cds,
            60 => Cdnskey,
            61 => Openpgpkey,
            62 => Csync,
            // 63-98
            99 => Spf,
            100 => Uinfo,
            101 => Uid,
            102 => Gid,
            103 => Unspec,
            104 => Nid,
            105 => L32,
            106 => L64,
            107 => Lp,
            108 => Eui48,
            109 => Eui64,
            // 110-248
            249 => Tkey,
            250 => Tsig,
            251 => Ixfr,
            252 => Axfr,
            253 => Mailb,
            254 => Maila,
            255 => Any,
            256 => Uri,
            257 => Caa,
            258 => Avc,
            // 259-32767
            32768 => Ta,
            32769 => Dlv,
            _ => Int(value)
        }
    }

    /// Returns an integer value for this type value.
    pub fn to_int(self) -> u16 {
        use self::RRType::*;

        match self {
            A => 1,
            Ns => 2,
            Md => 3,
            Mf => 4,
            Cname => 5,
            Soa => 6,
            Mb => 7,
            Mg => 8,
            Mr => 9,
            Null => 10,
            Wks => 11,
            Ptr => 12,
            Hinfo => 13,
            Minfo => 14,
            Mx => 15,
            Txt => 16,
            Rp => 17,
            Afsdb => 18,
            X25 => 19,
            Isdn => 20,
            Rt => 21,
            Nsap => 22,
            Nsapptr => 23,
            Sig => 24,
            Key => 25,
            Px => 26,
            Gpos => 27,
            Aaaa => 28,
            Loc => 29,
            Nxt => 30,
            Eid => 31,
            Nimloc => 32,
            Srv => 33,
            Atma => 34,
            Naptr => 35,
            Kx => 36,
            Cert => 37,
            A6 => 38,
            Dname => 39,
            Sink => 40,
            Opt => 41,
            Apl => 42,
            Ds => 43,
            Sshfp => 44,
            Ipseckey => 45,
            Rrsig => 46,
            Nsec => 47,
            Dnskey => 48,
            Dhcid => 49,
            Nsec3 => 50,
            Nsec3param => 51,
            Tlsa => 52,
            Smimea => 53,
            Hip => 55,
            Ninfo => 56,
            Rkey => 57,
            Talink => 58,
            Cds => 59,
            Cdnskey => 60,
            Openpgpkey => 61,
            Csync => 62,
            Spf => 99,
            Uinfo => 100,
            Uid => 101,
            Gid => 102,
            Unspec => 103,
            Nid => 104,
            L32 => 105,
            L64 => 106,
            Lp => 107,
            Eui48 => 108,
            Eui64 => 109,
            Tkey => 249,
            Tsig => 250,
            Ixfr => 251,
            Axfr => 252,
            Mailb => 253,
            Maila => 254,
            Any => 255,
            Uri => 256,
            Caa => 257,
            Avc => 258,
            Ta => 32768,
            Dlv => 32769,
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
        else if s.eq_ignore_ascii_case("NS") { Ok(Ns) }
        else if s.eq_ignore_ascii_case("MD") { Ok(Md) }
        else if s.eq_ignore_ascii_case("MF") { Ok(Mf) }
        else if s.eq_ignore_ascii_case("CNAME") { Ok(Cname) }
        else if s.eq_ignore_ascii_case("SOA") { Ok(Soa) }
        else if s.eq_ignore_ascii_case("MB") { Ok(Mb) }
        else if s.eq_ignore_ascii_case("MG") { Ok(Mg) }
        else if s.eq_ignore_ascii_case("MR") { Ok(Mr) }
        else if s.eq_ignore_ascii_case("NULL") { Ok(Null) }
        else if s.eq_ignore_ascii_case("WKS") { Ok(Wks) }
        else if s.eq_ignore_ascii_case("PTR") { Ok(Ptr) }
        else if s.eq_ignore_ascii_case("HINFO") { Ok(Hinfo) }
        else if s.eq_ignore_ascii_case("MINFO") { Ok(Minfo) }
        else if s.eq_ignore_ascii_case("MX") { Ok(Mx) }
        else if s.eq_ignore_ascii_case("TXT") { Ok(Txt) }
        else if s.eq_ignore_ascii_case("RP") { Ok(Rp) }
        else if s.eq_ignore_ascii_case("AFSDB") { Ok(Afsdb) }
        else if s.eq_ignore_ascii_case("X25") { Ok(X25) }
        else if s.eq_ignore_ascii_case("ISDN") { Ok(Isdn) }
        else if s.eq_ignore_ascii_case("RT") { Ok(Rt) }
        else if s.eq_ignore_ascii_case("NSAP") { Ok(Nsap) }
        else if s.eq_ignore_ascii_case("NSAP-PTR") { Ok(Nsapptr) }
        else if s.eq_ignore_ascii_case("SIG") { Ok(Sig) }
        else if s.eq_ignore_ascii_case("KEY") { Ok(Key) }
        else if s.eq_ignore_ascii_case("PX") { Ok(Px) }
        else if s.eq_ignore_ascii_case("GPOS") { Ok(Gpos) }
        else if s.eq_ignore_ascii_case("AAAA") { Ok(Aaaa) }
        else if s.eq_ignore_ascii_case("LOC") { Ok(Loc) }
        else if s.eq_ignore_ascii_case("NXT") { Ok(Nxt) }
        else if s.eq_ignore_ascii_case("EID") { Ok(Eid) }
        else if s.eq_ignore_ascii_case("NIMLOC") { Ok(Nimloc) }
        else if s.eq_ignore_ascii_case("SRV") { Ok(Srv) }
        else if s.eq_ignore_ascii_case("ATMA") { Ok(Atma) }
        else if s.eq_ignore_ascii_case("NAPTR") { Ok(Naptr) }
        else if s.eq_ignore_ascii_case("KX") { Ok(Kx) }
        else if s.eq_ignore_ascii_case("CERT") { Ok(Cert) }
        else if s.eq_ignore_ascii_case("A6") { Ok(A6) }
        else if s.eq_ignore_ascii_case("DNAME") { Ok(Dname) }
        else if s.eq_ignore_ascii_case("SINK") { Ok(Sink) }
        else if s.eq_ignore_ascii_case("OPT") { Ok(Opt) }
        else if s.eq_ignore_ascii_case("APL") { Ok(Apl) }
        else if s.eq_ignore_ascii_case("DS") { Ok(Ds) }
        else if s.eq_ignore_ascii_case("SSHFP") { Ok(Sshfp) }
        else if s.eq_ignore_ascii_case("IPSECKEY") { Ok(Ipseckey) }
        else if s.eq_ignore_ascii_case("RRSIG") { Ok(Rrsig) }
        else if s.eq_ignore_ascii_case("NSEC") { Ok(Nsec) }
        else if s.eq_ignore_ascii_case("DNSKEY") { Ok(Dnskey) }
        else if s.eq_ignore_ascii_case("DHCID") { Ok(Dhcid) }
        else if s.eq_ignore_ascii_case("NSEC3") { Ok(Nsec3) }
        else if s.eq_ignore_ascii_case("NSEC3PARAM") { Ok(Nsec3param) }
        else if s.eq_ignore_ascii_case("TLSA") { Ok(Tlsa) }
        else if s.eq_ignore_ascii_case("SMIMEA") { Ok(Smimea) }
        else if s.eq_ignore_ascii_case("HIP") { Ok(Hip) }
        else if s.eq_ignore_ascii_case("NINFO") { Ok(Ninfo) }
        else if s.eq_ignore_ascii_case("RKEY") { Ok(Rkey) }
        else if s.eq_ignore_ascii_case("TALINK") { Ok(Talink) }
        else if s.eq_ignore_ascii_case("CDS") { Ok(Cds) }
        else if s.eq_ignore_ascii_case("CDNSKEY") { Ok(Cdnskey) }
        else if s.eq_ignore_ascii_case("OPENPGPKEY") { Ok(Openpgpkey) }
        else if s.eq_ignore_ascii_case("CSYNC") { Ok(Csync) }
        else if s.eq_ignore_ascii_case("SPF") { Ok(Spf) }
        else if s.eq_ignore_ascii_case("UINFO") { Ok(Uinfo) }
        else if s.eq_ignore_ascii_case("UID") { Ok(Uid) }
        else if s.eq_ignore_ascii_case("GID") { Ok(Gid) }
        else if s.eq_ignore_ascii_case("UNSPEC") { Ok(Unspec) }
        else if s.eq_ignore_ascii_case("NID") { Ok(Nid) }
        else if s.eq_ignore_ascii_case("L32") { Ok(L32) }
        else if s.eq_ignore_ascii_case("L64") { Ok(L64) }
        else if s.eq_ignore_ascii_case("LP") { Ok(Lp) }
        else if s.eq_ignore_ascii_case("EUI48") { Ok(Eui48) }
        else if s.eq_ignore_ascii_case("EUI64") { Ok(Eui64) }
        else if s.eq_ignore_ascii_case("TKEY") { Ok(Tkey) }
        else if s.eq_ignore_ascii_case("TSIG") { Ok(Tsig) }
        else if s.eq_ignore_ascii_case("IXFR") { Ok(Ixfr) }
        else if s.eq_ignore_ascii_case("AXFR") { Ok(Axfr) }
        else if s.eq_ignore_ascii_case("MAILB") { Ok(Mailb) }
        else if s.eq_ignore_ascii_case("MAILA") { Ok(Maila) }
        else if s.eq_ignore_ascii_case("ANY") { Ok(Any) }
        else if s.eq_ignore_ascii_case("URI") { Ok(Uri) }
        else if s.eq_ignore_ascii_case("CAA") { Ok(Caa) }
        else if s.eq_ignore_ascii_case("AVC") { Ok(Avc) }
        else if s.eq_ignore_ascii_case("TA") { Ok(Ta) }
        else if s.eq_ignore_ascii_case("DLV") { Ok(Dlv) }
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
            Ns => "NS".fmt(f),
            Md => "MD".fmt(f),
            Mf => "MF".fmt(f),
            Cname => "CNAME".fmt(f),
            Soa => "SOA".fmt(f),
            Mb => "MB".fmt(f),
            Mg => "MG".fmt(f),
            Mr => "MR".fmt(f),
            Null => "NULL".fmt(f),
            Wks => "WKS".fmt(f),
            Ptr => "PTR".fmt(f),
            Hinfo => "HINFO".fmt(f),
            Minfo => "MINFO".fmt(f),
            Mx => "MX".fmt(f),
            Txt => "TXT".fmt(f),
            Rp => "RP".fmt(f),
            Afsdb => "AFSDB".fmt(f),
            X25 => "X25".fmt(f),
            Isdn => "ISDN".fmt(f),
            Rt => "RT".fmt(f),
            Nsap => "NSAP".fmt(f),
            Nsapptr => "NSAP-PTR".fmt(f),
            Sig => "SIG".fmt(f),
            Key => "KEY".fmt(f),
            Px => "PX".fmt(f),
            Gpos => "GPOS".fmt(f),
            Aaaa => "AAAA".fmt(f),
            Loc => "LOC".fmt(f),
            Nxt => "NXT".fmt(f),
            Eid => "EID".fmt(f),
            Nimloc => "NIMLOC".fmt(f),
            Srv => "SRV".fmt(f),
            Atma => "ATMA".fmt(f),
            Naptr => "NAPTR".fmt(f),
            Kx => "KX".fmt(f),
            Cert => "CERT".fmt(f),
            A6 => "A6".fmt(f),
            Dname => "DNAME".fmt(f),
            Sink => "SINK".fmt(f),
            Opt => "OPT".fmt(f),
            Apl => "APL".fmt(f),
            Ds => "DS".fmt(f),
            Sshfp => "SSHFP".fmt(f),
            Ipseckey => "IPSECKEY".fmt(f),
            Rrsig => "RRSIG".fmt(f),
            Nsec => "NSEC".fmt(f),
            Dnskey => "DNSKEY".fmt(f),
            Dhcid => "DHCID".fmt(f),
            Nsec3 => "NSEC3".fmt(f),
            Nsec3param => "NSEC3PARAM".fmt(f),
            Tlsa => "TLSA".fmt(f),
            Smimea => "SMIMEA".fmt(f),
            Hip => "HIP".fmt(f),
            Ninfo => "NINFO".fmt(f),
            Rkey => "RKEY".fmt(f),
            Talink => "TALINK".fmt(f),
            Cds => "CDS".fmt(f),
            Cdnskey => "CDNSKEY".fmt(f),
            Openpgpkey => "OPENPGPKEY".fmt(f),
            Csync => "CSYNC".fmt(f),
            Spf => "SPF".fmt(f),
            Uinfo => "UINFO".fmt(f),
            Uid => "UID".fmt(f),
            Gid => "GID".fmt(f),
            Unspec => "UNSPEC".fmt(f),
            Nid => "NID".fmt(f),
            L32 => "L32".fmt(f),
            L64 => "L64".fmt(f),
            Lp => "LP".fmt(f),
            Eui48 => "EUI48".fmt(f),
            Eui64 => "EUI64".fmt(f),
            Tkey => "TKEY".fmt(f),
            Tsig => "TSIG".fmt(f),
            Ixfr => "IXFR".fmt(f),
            Axfr => "AXFR".fmt(f),
            Mailb => "MAILB".fmt(f),
            Maila => "MAILA".fmt(f),
            Any => "ANY".fmt(f),
            Uri => "URI".fmt(f),
            Caa => "CAA".fmt(f),
            Avc => "AVC".fmt(f),
            Ta => "TA".fmt(f),
            Dlv => "DLV".fmt(f),
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

