//! Resource Record (RR) TYPEs


//------------ Rtype ---------------------------------------------------------

int_enum!{
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
    (Ns => 2, b"NS")

    /// A mail destination.
    ///
    /// (Obsolete – use MX)
    (Md => 3, b"MD")

    /// A mail forwarder.
    ///
    /// (Obsolete – use MX)
    (Mf => 4, b"MF")

    /// The canonical name for an alias
    (Cname => 5, b"CNAME")

    /// Marks the start of a zone of authority.
    (Soa => 6, b"SOA")

    /// A mailbox domain name.
    ///
    /// (Experimental.)
    (Mb =>  7, b"MB")

    /// A mail group member
    ///
    /// (Experimental.)
    (Mg => 8, b"MG")

    /// A mail rename domain name.
    ///
    /// (Experimental.)
    (Mr => 9, b"MR")
    
    /// A null resource record.
    ///
    /// (Experimental.)
    (Null =>  10, b"NULL")

    /// A well known service description.
    (Wks => 11, b"WKS")

    /// A domain name pointer.
    (Ptr => 12, b"PTR")

    /// Host information.
    (Hinfo => 13, b"HINFO")

    /// Mailbox or mail list information.
    (Minfo => 14, b"MINFO")

    /// Mail exchange.
    (Mx => 15, b"MX")

    /// Text strings.
    (Txt => 16, b"TXT")
    
    /// For Responsible Person.
    ///
    /// See RFC 1183
    (Rp => 17, b"RP")

    /// For AFS Data Base location.
    ///
    /// See RFC 1183 and RFC 5864.
    (Afsdb => 18, b"AFSDB")

    /// For X.25 PSDN address.
    ///
    /// See RFC 1183.
    (X25 => 19, b"X25")

    /// For ISDN address.
    ///
    /// See RFC 1183.
    (Isdn => 20, b"ISDN")

    /// For Route Through.
    ///
    /// See RFC 1183
    (Rt => 21, b"RT")

    /// For SNAP address, NSAP style A record.
    ///
    /// See RFC 1706.
    (Nsap => 22, b"NSAP")
    
    /// For domain name pointer, NSAP style.
    ///
    /// See RFC 1348, RFC 1637, RFC 1706.
    (Nsapptr => 23, b"NSAPPTR")

    /// For security signature.
    (Sig => 24, b"SIG")

    /// For security key.
    (Key => 25, b"KEY")

    /// X.400 mail mapping information.
    ///
    /// See RFC 2163.
    (Px => 26, b"PX")

    /// Geographical position.
    ///
    /// See RFC 1712
    (Gpos => 27, b"GPOS")
    
    /// IPv6 address.
    ///
    /// See RFC 3596.
    (Aaaa =>  28, b"AAAA")

    /// Location information.
    ///
    /// See RFC 1876.
    (Loc => 29, b"LOC")

    /// Next domain.
    ///
    /// (Obsolete.)
    ///
    /// See RFC 3755 and RFC 2535.
    (Nxt => 30, b"NXT")

    /// Endpoint identifier.
    (Eid => 31, b"EID")

    /// Nimrod locator.
    (Nimloc => 32, b"NIMLOC")

    /// Server selection.
    ///
    /// See RFC 2782.
    (Srv => 33, b"SRV")

    /// ATM address.
    (Atma => 34, b"ATMA")

    /// Naming authority pointer.
    ///
    /// See RFC 2915, RFC 2168, and RFC 3403.
    (Naptr => 35, b"NAPTR")

    /// Key exchanger.
    ///
    /// See RFC 2230.
    (Kx => 36, b"KX")

    /// CERT
    ///
    /// See RFC 4398.
    (Cert => 37, b"CERT")

    /// A6.
    ///
    /// (Obsolete – use AAAA.)
    ///
    /// See RFC 3226, RFC 2874, and RFC 6563.
    (A6 => 38, b"A6")

    /// DNAME.
    ///
    /// See RFC 6672.
    (Dname => 39, b"DNAME")

    /// SINK.
    (Sink => 40, b"SINK")

    /// OPT.
    ///
    /// See RFC 6891 and RFC 3225.
    (Opt => 41, b"OPT")

    /// APL.
    ///
    /// See RFC 3123.
    (Apl => 42, b"APL")

    /// Delegation signer.
    ///
    /// See RFC 4034 and RFC 3658.
    (Ds => 43, b"DS")

    /// SSH key fingerprint.
    ///
    /// See RFC 4255.
    (Sshfp => 44, b"SSHFP")

    /// IPSECKEY
    ///
    /// See RFC 4255.
    (Ipseckey => 45, b"IPSECKEY")

    /// RRSIG.
    ///
    /// See RFC 4034 and RFC 3755.
    (Rrsig => 46, b"RRSIG")

    /// NSEC.
    ///
    /// See RFC 4034 and RFC 3755.
    (Nsec => 47, b"NSEC")

    /// DNSKEY.
    ///
    /// See RFC 4034 and RFC 3755.
    (Dnskey => 48, b"DNSKEY")

    /// DHCID.
    ///
    /// See RFC 4701.
    (Dhcid => 49, b"DHCID")

    /// NSEC3
    ///
    /// See RFC 5155.
    (Nsec3 => 50, b"NSEC3")

    /// NSEC3PARAM.
    ///
    /// See RFC 5155.
    (Nsec3param => 51, b"NSEC3PARAM")
    
    /// TLSA.
    ///
    /// See RFC 6698.
    (Tlsa => 52, b"TLSA")

    /// S/MIME cert association.
    ///
    /// See draft-ietf-dane-smime.
    (Smimea => 53, b"SMIMEA")

    /// Host Identity Protocol.
    ///
    /// See RFC 5205.
    (Hip => 55, b"HIP")

    /// NINFO.
    (Ninfo => 56, b"NINFO")

    /// RKEY.
    (Rkey => 57, b"RKEY")

    /// Trust Anchor Link
    (Talink => 58, b"TALINK")

    /// Child DS.
    ///
    /// See RFC 7344.
    (Cds => 59, b"CDS")

    /// DNSKEY(s) the child wants reflected in DS.
    ///
    /// See RFC 7344.
    (Cdnskey => 60, b"CDNSKEY")
    
    /// OpenPGP key.
    ///
    /// See draft-ietf-dane-openpgpkey.
    (Openpgpkey => 61, b"OPENPGPKEY")

    /// Child-to-parent synchronization.
    ///
    /// See RFC 7477.
    (Csync => 62, b"CSYNC")

    /// Message digest for DNS zone.
    ///
    /// See draft-wessels-dns-zone-digest.
    (Zonemd => 63, b"ZONEMD")

    /// General Purpose Service Endpoints.
    ///
    /// See draft-ietf-dnsop-svcb-https.
    (Svcb => 64, b"SVCB")

    /// HTTPS Specific Service Endpoints.
    ///
    /// See draft-ietf-dnsop-svcb-https.
    (Https => 65, b"HTTPS")

    /// SPF.
    ///
    /// RFC 7208.
    (Spf => 99, b"SPF")

    /// UINFO.
    ///
    /// IANA-Reserved.
    (Uinfo => 100, b"UINFO")
    
    /// UID.
    ///
    /// IANA-Reserved.
    (Uid => 101, b"UID")

    /// GID.
    ///
    /// IANA-Reserved.
    (Gid => 102, b"GID")

    /// UNSPEC.
    ///
    /// IANA-Reserved.
    (Unspec => 103, b"UNSPEC")

    /// NID.
    ///
    /// See RFC 6742.
    (Nid => 104, b"NID")

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
    (Lp => 107, b"LP")

    /// An EUI-48 address.
    ///
    /// See RFC 7043.
    (Eui48 => 108, b"EUI48")

    /// An EUI-64 address.
    ///
    /// See RFC 7043.
    (Eui64 => 109, b"EUI64")
    
    /// Transaction key.
    ///
    /// See RFC 2930.
    (Tkey => 249, b"TKEY")
    
    /// Transaction signature.
    ///
    /// See RFC 2845.
    (Tsig => 250, b"TSIG")

    /// Incremental transfer.
    ///
    /// See RFC 1995.
    (Ixfr => 251, b"IXFR")
    
    /// Transfer of entire zone.
    ///
    /// See RFC 1035 and RFC 5936.
    (Axfr => 252, b"AXFR")

    /// Mailbox-related RRs (MB, MG, or MR).
    (Mailb => 253, b"MAILB")

    /// Mail agent RRS.
    ///
    /// (Obsolete – see MX.)
    (Maila => 254, b"MAILA")

    /// A request for all records the server/cache has available.
    ///
    /// See RFC 1035 and RFC 6895.
    (Any => 255, b"ANY")

    /// URI.
    ///
    /// See RFC 7553.
    (Uri => 256, b"URI")

    /// Certification Authority Restriction.
    ///
    /// See RFC 6844.
    (Caa => 257, b"CAA")

    /// Application visibility and control.
    (Avc => 258, b"AVC")

    /// Digital Object Architecture
    ///
    /// See draft-durand-doa-over-dns.
    (Doa => 259, b"DOA")

    /// DNSSEC trust authorities.
    (Ta => 32768, b"TA")

    /// DNSSEC lookaside validation.
    ///
    /// See RFC 4431
    (Dlv => 32769, b"DLV")
}

int_enum_str_with_prefix!(
    Rtype, "TYPE", b"TYPE", u16, "unknown record type"
);

