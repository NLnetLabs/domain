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
    (A => 1, "A")

    /// An authoritative name server.
    (NS => 2, "NS")

    /// A mail destination.
    ///
    /// (Obsolete – use MX)
    (MD => 3, "MD")

    /// A mail forwarder.
    ///
    /// (Obsolete – use MX)
    (MF => 4, "MF")

    /// The canonical name for an alias
    (CNAME => 5, "CNAME")

    /// Marks the start of a zone of authority.
    (SOA => 6, "SOA")

    /// A mailbox domain name.
    ///
    /// (Experimental.)
    (MB =>  7, "MB")

    /// A mail group member
    ///
    /// (Experimental.)
    (MG => 8, "MG")

    /// A mail rename domain name.
    ///
    /// (Experimental.)
    (MR => 9, "MR")

    /// A null resource record.
    ///
    /// (Experimental.)
    (NULL =>  10, "NULL")

    /// A well known service description.
    (WKS => 11, "WKS")

    /// A domain name pointer.
    (PTR => 12, "PTR")

    /// Host information.
    (HINFO => 13, "HINFO")

    /// Mailbox or mail list information.
    (MINFO => 14, "MINFO")

    /// Mail exchange.
    (MX => 15, "MX")

    /// Text strings.
    (TXT => 16, "TXT")

    /// For Responsible Person.
    ///
    /// See RFC 1183
    (RP => 17, "RP")

    /// For AFS Data Base location.
    ///
    /// See RFC 1183 and RFC 5864.
    (AFSDB => 18, "AFSDB")

    /// For X.25 PSDN address.
    ///
    /// See RFC 1183.
    (X25 => 19, "X25")

    /// For ISDN address.
    ///
    /// See RFC 1183.
    (ISDN => 20, "ISDN")

    /// For Route Through.
    ///
    /// See RFC 1183
    (RT => 21, "RT")

    /// For SNAP address, NSAP style A record.
    ///
    /// See RFC 1706.
    (NSAP => 22, "NSAP")

    /// For domain name pointer, NSAP style.
    ///
    /// See RFC 1348, RFC 1637, RFC 1706.
    (NSAPPTR => 23, "NSAPPTR")

    /// For security signature.
    (SIG => 24, "SIG")

    /// For security key.
    (KEY => 25, "KEY")

    /// X.400 mail mapping information.
    ///
    /// See RFC 2163.
    (PX => 26, "PX")

    /// Geographical position.
    ///
    /// See RFC 1712
    (GPOS => 27, "GPOS")

    /// IPv6 address.
    ///
    /// See RFC 3596.
    (AAAA =>  28, "AAAA")

    /// Location information.
    ///
    /// See RFC 1876.
    (LOC => 29, "LOC")

    /// Next domain.
    ///
    /// (Obsolete.)
    ///
    /// See RFC 3755 and RFC 2535.
    (NXT => 30, "NXT")

    /// Endpoint identifier.
    (EID => 31, "EID")

    /// Nimrod locator.
    (NIMLOC => 32, "NIMLOC")

    /// Server selection.
    ///
    /// See RFC 2782.
    (SRV => 33, "SRV")

    /// ATM address.
    (ATMA => 34, "ATMA")

    /// Naming authority pointer.
    ///
    /// See RFC 2915, RFC 2168, and RFC 3403.
    (NAPTR => 35, "NAPTR")

    /// Key exchanger.
    ///
    /// See RFC 2230.
    (KX => 36, "KX")

    /// CERT
    ///
    /// See RFC 4398.
    (CERT => 37, "CERT")

    /// A6.
    ///
    /// (Obsolete – use AAAA.)
    ///
    /// See RFC 3226, RFC 2874, and RFC 6563.
    (A6 => 38, "A6")

    /// DNAME.
    ///
    /// See RFC 6672.
    (DNAME => 39, "DNAME")

    /// SINK.
    (SINK => 40, "SINK")

    /// OPT.
    ///
    /// See RFC 6891 and RFC 3225.
    (OPT => 41, "OPT")

    /// APL.
    ///
    /// See RFC 3123.
    (APL => 42, "APL")

    /// Delegation signer.
    ///
    /// See RFC 4034 and RFC 3658.
    (DS => 43, "DS")

    /// SSH key fingerprint.
    ///
    /// See RFC 4255.
    (SSHFP => 44, "SSHFP")

    /// IPSECKEY
    ///
    /// See RFC 4255.
    (IPSECKEY => 45, "IPSECKEY")

    /// RRSIG.
    ///
    /// See RFC 4034 and RFC 3755.
    (RRSIG => 46, "RRSIG")

    /// NSEC.
    ///
    /// See RFC 4034 and RFC 3755.
    (NSEC => 47, "NSEC")

    /// DNSKEY.
    ///
    /// See RFC 4034 and RFC 3755.
    (DNSKEY => 48, "DNSKEY")

    /// DHCID.
    ///
    /// See RFC 4701.
    (DHCID => 49, "DHCID")

    /// NSEC3
    ///
    /// See RFC 5155.
    (NSEC3 => 50, "NSEC3")

    /// NSEC3PARAM.
    ///
    /// See RFC 5155.
    (NSEC3PARAM => 51, "NSEC3PARAM")

    /// TLSA.
    ///
    /// See RFC 6698.
    (TLSA => 52, "TLSA")

    /// S/MIME cert association.
    ///
    /// See draft-ietf-dane-smime.
    (SMIMEA => 53, "SMIMEA")

    /// Host Identity Protocol.
    ///
    /// See RFC 5205.
    (HIP => 55, "HIP")

    /// NINFO.
    (NINFO => 56, "NINFO")

    /// RKEY.
    (RKEY => 57, "RKEY")

    /// Trust Anchor Link
    (TALINK => 58, "TALINK")

    /// Child DS.
    ///
    /// See RFC 7344.
    (CDS => 59, "CDS")

    /// DNSKEY(s) the child wants reflected in DS.
    ///
    /// See RFC 7344.
    (CDNSKEY => 60, "CDNSKEY")

    /// OpenPGP key.
    ///
    /// See draft-ietf-dane-openpgpkey.
    (OPENPGPKEY => 61, "OPENPGPKEY")

    /// Child-to-parent synchronization.
    ///
    /// See RFC 7477.
    (CSYNC => 62, "CSYNC")

    /// Message digest for DNS zone.
    ///
    /// See draft-wessels-dns-zone-digest.
    (ZONEMD => 63, "ZONEMD")

    /// General Purpose Service Endpoints.
    ///
    /// See draft-ietf-dnsop-svcb-httpssvc
    (SVCB => 64, "SVCB")

    /// HTTPS Specific Service Endpoints.
    ///
    /// See draft-ietf-dnsop-svcb-httpssvc
    (HTTPS => 65, "HTTPS")

    /// SPF.
    ///
    /// RFC 7208.
    (SPF => 99, "SPF")

    /// UINFO.
    ///
    /// IANA-Reserved.
    (UINFO => 100, "UINFO")

    /// UID.
    ///
    /// IANA-Reserved.
    (UID => 101, "UID")

    /// GID.
    ///
    /// IANA-Reserved.
    (GID => 102, "GID")

    /// UNSPEC.
    ///
    /// IANA-Reserved.
    (UNSPEC => 103, "UNSPEC")

    /// NID.
    ///
    /// See RFC 6742.
    (NID => 104, "NID")

    /// L32.
    ///
    /// See RFC 6742.
    (L32 => 105, "L32")

    /// L64.
    ///
    /// See RFC 6742.
    (L64 => 106, "L64")

    /// LP.
    ///
    /// See RFC 6742.
    (LP => 107, "LP")

    /// An EUI-48 address.
    ///
    /// See RFC 7043.
    (EUI48 => 108, "EUI48")

    /// An EUI-64 address.
    ///
    /// See RFC 7043.
    (EUI64 => 109, "EUI64")

    /// Transaction key.
    ///
    /// See RFC 2930.
    (TKEY => 249, "TKEY")

    /// Transaction signature.
    ///
    /// See RFC 2845.
    (TSIG => 250, "TSIG")

    /// Incremental transfer.
    ///
    /// See RFC 1995.
    (IXFR => 251, "IXFR")

    /// Transfer of entire zone.
    ///
    /// See RFC 1035 and RFC 5936.
    (AXFR => 252, "AXFR")

    /// Mailbox-related RRs (MB, MG, or MR).
    (MAILB => 253, "MAILB")

    /// Mail agent RRS.
    ///
    /// (Obsolete – see MX.)
    (MAILA => 254, "MAILA")

    /// A request for all records the server/cache has available.
    ///
    /// See RFC 1035 and RFC 6895.
    (ANY => 255, "ANY")

    /// URI.
    ///
    /// See RFC 7553.
    (URI => 256, "URI")

    /// Certification Authority Restriction.
    ///
    /// See RFC 6844.
    (CAA => 257, "CAA")

    /// Application visibility and control.
    (AVC => 258, "AVC")

    /// Digital Object Architecture
    ///
    /// See draft-durand-doa-over-dns.
    (DOA => 259, "DOA")

    /// DNSSEC trust authorities.
    (TA => 32768, "TA")

    /// DNSSEC lookaside validation.
    ///
    /// See RFC 4431
    (DLV => 32769, "DLV")
}

int_enum_str_with_prefix!(Rtype, "TYPE", b"TYPE", u16, "unknown record type");
int_enum_show_with_prefix!(Rtype, "TYPE");
