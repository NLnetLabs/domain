//! Resource Record (RR) TYPEs

//------------ Rtype ---------------------------------------------------------

int_enum! {
    /// Resource Record Types.
    ///
    /// Each resource records has a 16 bit type value indicating what kind of
    /// information is represented by the record. Normal query includes the
    /// type of record information is requested for. A few aditional types,
    /// called query types, are defined as well and can only be used in
    /// questions. This type represents both these types.
    ///
    /// The currently assigned values are maintained in an [IANA registry].
    /// This type is complete as of 2019-01-28.
    ///
    /// [IANA registry]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    ///
    /// In order to avoid confusion over capitalization, the mnemonics are
    /// treated as single acronyms and therefore all variant names are spelled
    /// with an initial capital letter in accordance with the Rust naming
    /// guidelines.
    =>
    Rtype, u16;

    /// A host address.
    (A => 1, b"A")

    /// An authoritative name server.
    (NS => 2, b"NS")

    /// A mail destination.
    ///
    /// (Obsolete – use MX)
    (MD => 3, b"MD")

    /// A mail forwarder.
    ///
    /// (Obsolete – use MX)
    (MF => 4, b"MF")

    /// The canonical name for an alias
    (CNAME => 5, b"CNAME")

    /// Marks the start of a zone of authority.
    (SOA => 6, b"SOA")

    /// A mailbox domain name.
    ///
    /// (Experimental.)
    (MB =>  7, b"MB")

    /// A mail group member
    ///
    /// (Experimental.)
    (MG => 8, b"MG")

    /// A mail rename domain name.
    ///
    /// (Experimental.)
    (MR => 9, b"MR")

    /// A null resource record.
    ///
    /// (Experimental.)
    (NULL =>  10, b"NULL")

    /// A well known service description.
    (WKS => 11, b"WKS")

    /// A domain name pointer.
    (PTR => 12, b"PTR")

    /// Host information.
    (HINFO => 13, b"HINFO")

    /// Mailbox or mail list information.
    (MINFO => 14, b"MINFO")

    /// Mail exchange.
    (MX => 15, b"MX")

    /// Text strings.
    (TXT => 16, b"TXT")

    /// For Responsible Person.
    ///
    /// See RFC 1183
    (RP => 17, b"RP")

    /// For AFS Data Base location.
    ///
    /// See RFC 1183 and RFC 5864.
    (AFSDB => 18, b"AFSDB")

    /// For X.25 PSDN address.
    ///
    /// See RFC 1183.
    (X25 => 19, b"X25")

    /// For ISDN address.
    ///
    /// See RFC 1183.
    (ISDN => 20, b"ISDN")

    /// For Route Through.
    ///
    /// See RFC 1183
    (RT => 21, b"RT")

    /// For SNAP address, NSAP style A record.
    ///
    /// See RFC 1706.
    (NSAP => 22, b"NSAP")

    /// For domain name pointer, NSAP style.
    ///
    /// See RFC 1348, RFC 1637, RFC 1706.
    (NSAPPTR => 23, b"NSAPPTR")

    /// For security signature.
    (SIG => 24, b"SIG")

    /// For security key.
    (KEY => 25, b"KEY")

    /// X.400 mail mapping information.
    ///
    /// See RFC 2163.
    (PX => 26, b"PX")

    /// Geographical position.
    ///
    /// See RFC 1712
    (GPOS => 27, b"GPOS")

    /// IPv6 address.
    ///
    /// See RFC 3596.
    (AAAA =>  28, b"AAAA")

    /// Location information.
    ///
    /// See RFC 1876.
    (LOC => 29, b"LOC")

    /// Next domain.
    ///
    /// (Obsolete.)
    ///
    /// See RFC 3755 and RFC 2535.
    (NXT => 30, b"NXT")

    /// Endpoint identifier.
    (EID => 31, b"EID")

    /// Nimrod locator.
    (NIMLOC => 32, b"NIMLOC")

    /// Server selection.
    ///
    /// See RFC 2782.
    (SRV => 33, b"SRV")

    /// ATM address.
    (ATMA => 34, b"ATMA")

    /// Naming authority pointer.
    ///
    /// See RFC 2915, RFC 2168, and RFC 3403.
    (NAPTR => 35, b"NAPTR")

    /// Key exchanger.
    ///
    /// See RFC 2230.
    (KX => 36, b"KX")

    /// CERT
    ///
    /// See RFC 4398.
    (CERT => 37, b"CERT")

    /// A6.
    ///
    /// (Obsolete – use AAAA.)
    ///
    /// See RFC 3226, RFC 2874, and RFC 6563.
    (A6 => 38, b"A6")

    /// DNAME.
    ///
    /// See RFC 6672.
    (DNAME => 39, b"DNAME")

    /// SINK.
    (SINK => 40, b"SINK")

    /// OPT.
    ///
    /// See RFC 6891 and RFC 3225.
    (OPT => 41, b"OPT")

    /// APL.
    ///
    /// See RFC 3123.
    (APL => 42, b"APL")

    /// Delegation signer.
    ///
    /// See RFC 4034 and RFC 3658.
    (DS => 43, b"DS")

    /// SSH key fingerprint.
    ///
    /// See RFC 4255.
    (SSHFP => 44, b"SSHFP")

    /// IPSECKEY
    ///
    /// See RFC 4255.
    (IPSECKEY => 45, b"IPSECKEY")

    /// RRSIG.
    ///
    /// See RFC 4034 and RFC 3755.
    (RRSIG => 46, b"RRSIG")

    /// NSEC.
    ///
    /// See RFC 4034 and RFC 3755.
    (NSEC => 47, b"NSEC")

    /// DNSKEY.
    ///
    /// See RFC 4034 and RFC 3755.
    (DNSKEY => 48, b"DNSKEY")

    /// DHCID.
    ///
    /// See RFC 4701.
    (DHCID => 49, b"DHCID")

    /// NSEC3
    ///
    /// See RFC 5155.
    (NSEC3 => 50, b"NSEC3")

    /// NSEC3PARAM.
    ///
    /// See RFC 5155.
    (NSEC3PARAM => 51, b"NSEC3PARAM")

    /// TLSA.
    ///
    /// See RFC 6698.
    (TLSA => 52, b"TLSA")

    /// S/MIME cert association.
    ///
    /// See draft-ietf-dane-smime.
    (SMIMEA => 53, b"SMIMEA")

    /// Host Identity Protocol.
    ///
    /// See RFC 5205.
    (HIP => 55, b"HIP")

    /// NINFO.
    (NINFO => 56, b"NINFO")

    /// RKEY.
    (RKEY => 57, b"RKEY")

    /// Trust Anchor Link
    (TALINK => 58, b"TALINK")

    /// Child DS.
    ///
    /// See RFC 7344.
    (CDS => 59, b"CDS")

    /// DNSKEY(s) the child wants reflected in DS.
    ///
    /// See RFC 7344.
    (CDNSKEY => 60, b"CDNSKEY")

    /// OpenPGP key.
    ///
    /// See draft-ietf-dane-openpgpkey.
    (OPENPGPKEY => 61, b"OPENPGPKEY")

    /// Child-to-parent synchronization.
    ///
    /// See RFC 7477.
    (CSYNC => 62, b"CSYNC")

    /// Message digest for DNS zone.
    ///
    /// See draft-wessels-dns-zone-digest.
    (ZONEMD => 63, b"ZONEMD")

    /// General Purpose Service Endpoints.
    ///
    /// See draft-ietf-dnsop-svcb-httpssvc
    (SVCB => 64, b"SVCB")

    /// HTTPS Specific Service Endpoints.
    ///
    /// See draft-ietf-dnsop-svcb-httpssvc
    (HTTPS => 65, b"HTTPS")

    /// SPF.
    ///
    /// RFC 7208.
    (SPF => 99, b"SPF")

    /// UINFO.
    ///
    /// IANA-Reserved.
    (UINFO => 100, b"UINFO")

    /// UID.
    ///
    /// IANA-Reserved.
    (UID => 101, b"UID")

    /// GID.
    ///
    /// IANA-Reserved.
    (GID => 102, b"GID")

    /// UNSPEC.
    ///
    /// IANA-Reserved.
    (UNSPEC => 103, b"UNSPEC")

    /// NID.
    ///
    /// See RFC 6742.
    (NID => 104, b"NID")

    /// L32.
    ///
    /// See RFC 6742.
    (L32 => 105, b"L32")

    /// L64.
    ///
    /// See RFC 6742.
    (L64 => 106, b"L64")

    /// LP.
    ///
    /// See RFC 6742.
    (LP => 107, b"LP")

    /// An EUI-48 address.
    ///
    /// See RFC 7043.
    (EUI48 => 108, b"EUI48")

    /// An EUI-64 address.
    ///
    /// See RFC 7043.
    (EUI64 => 109, b"EUI64")

    /// Transaction key.
    ///
    /// See RFC 2930.
    (TKEY => 249, b"TKEY")

    /// Transaction signature.
    ///
    /// See RFC 2845.
    (TSIG => 250, b"TSIG")

    /// Incremental transfer.
    ///
    /// See RFC 1995.
    (IXFR => 251, b"IXFR")

    /// Transfer of entire zone.
    ///
    /// See RFC 1035 and RFC 5936.
    (AXFR => 252, b"AXFR")

    /// Mailbox-related RRs (MB, MG, or MR).
    (MAILB => 253, b"MAILB")

    /// Mail agent RRS.
    ///
    /// (Obsolete – see MX.)
    (MAILA => 254, b"MAILA")

    /// A request for all records the server/cache has available.
    ///
    /// See RFC 1035 and RFC 6895.
    (ANY => 255, b"ANY")

    /// URI.
    ///
    /// See RFC 7553.
    (URI => 256, b"URI")

    /// Certification Authority Restriction.
    ///
    /// See RFC 6844.
    (CAA => 257, b"CAA")

    /// Application visibility and control.
    (AVC => 258, b"AVC")

    /// Digital Object Architecture
    ///
    /// See draft-durand-doa-over-dns.
    (DOA => 259, b"DOA")

    /// DNSSEC trust authorities.
    (TA => 32768, b"TA")

    /// DNSSEC lookaside validation.
    ///
    /// See RFC 4431
    (DLV => 32769, b"DLV")
}

int_enum_str_with_prefix!(Rtype, "TYPE", b"TYPE", u16, "unknown record type");

pub trait IsGlue {
    fn is_glue(&self) -> bool;
}

impl IsGlue for Rtype {
    fn is_glue(&self) -> bool {
        matches!(*self, Rtype::A | Rtype::AAAA)
    }
}