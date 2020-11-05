//! Extended DNS Error

//------------ Extended Error Code ---------------------------------------------------------

int_enum! {
    /// Extended DNS error codes.
    ///
    /// A complementary data can be put in EDNS opt, providing
    /// additional information about the cause of DNS errors. Defined
    /// in [RFC 8914]. Current registered values can be found in [IANA
    /// registry].
    ///
    /// [RFC 8914]: https://tools.ietf.org/html/rfc8914
    /// [IANA registry]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes
    =>
    ExtendedErrorCode, u16;

    /// The error in question falls into a category that does not
    /// match known extended error codes. Implementations SHOULD
    /// include an EXTRA-TEXT value to augment this error code with
    /// additional information.
    (Other => 0, b"Other Error")

    /// The resolver attempted to perform DNSSEC validation, but a DNSKEY
    /// RRset contained only unsupported DNSSEC algorithms.
    (UnsupportedDnskeyAlgorithm => 1, b"Unsupported DNSKEY Algorithm")

    /// The resolver attempted to perform DNSSEC validation, but a DS
    /// RRset contained only unsupported Digest Types.
    (UnsupportedDsDigestType => 2, b"Unsupported DS Digest Type")

    /// The resolver was unable to resolve the answer within its time
    /// limits and decided to answer with previously cached data
    /// instead of answering with an error. This is typically caused
    /// by problems communicating with an authoritative server,
    /// possibly as result of a denial of service (DoS) attack against
    /// another network. (See also Code 19.)
    (StaleAnswer => 3, b"Stale Answer")

    /// For policy reasons (legal obligation or malware filtering, for
    /// instance), an answer was forged. Note that this should be
    /// used when an answer is still provided, not when failure
    /// codes are returned instead. See Blocked (15), Censored
    /// (16), and Filtered (17) for use when returning other
    /// response codes.
    (ForgedAnswer => 4, b"Forged Answer")

    /// The resolver attempted to perform DNSSEC validation, but
    /// validation ended in the Indeterminate state [RFC4035].
    (DnssecIndeterminate => 5, b"DNSSEC Indeterminate")

    /// The resolver attempted to perform DNSSEC validation, but
    /// validation ended in the Bogus state.
    (DnssecBogus => 6, b"DNSSEC Bogus")

    /// The resolver attempted to perform DNSSEC validation, but no
    /// signatures are presently valid and some (often all) are
    /// expired.
    (SignatureExpired => 7, b"Signature Expired")

    /// The resolver attempted to perform DNSSEC validation, but no
    /// signatures are presently valid and at least some are not yet
    /// valid.
    (SignatureNotYetValid => 8, b"Signature Not Yet Valid")

    /// A DS record existed at a parent, but no supported matching
    /// DNSKEY record could be found for the child.
    (DnskeyMissing => 9, b"DNSKEY Missing")

    /// The resolver attempted to perform DNSSEC validation, but no
    /// RRSIGs could be found for at least one RRset where RRSIGs were
    /// expected.
    (RrsigsMissing => 10, b"RRSIGs Missing")

    /// The resolver attempted to perform DNSSEC validation, but no
    /// Zone Key Bit was set in a DNSKEY.
    (NoZoneKeyBitSet => 11, b"No Zone Key Bit Set")

    /// The resolver attempted to perform DNSSEC validation, but the
    /// requested data was missing and a covering NSEC or NSEC3 was
    /// not provided.
    (NsecMissing => 12, b"NSEC Missing")

    /// The resolver is returning the SERVFAIL RCODE from its cache.
    (CachedError => 13, b"Cached Error")

    /// The server is unable to answer the query, as it was not fully
    /// functional when the query was received.
    (NotReady => 14, b"Not Ready")

    /// The server is unable to respond to the request because the
    /// domain is on a blocklist due to an internal security policy
    /// imposed by the operator of the server resolving or forwarding
    /// the query.
    (Blocked => 15, b"Blocked")

    /// The server is unable to respond to the request because the
    /// domain is on a blocklist due to an external requirement
    /// imposed by an entity other than the operator of the server
    /// resolving or forwarding the query. Note that how the imposed
    /// policy is applied is irrelevant (in-band DNS filtering, court
    /// order, etc.).
    (Censored => 16, b"Censored")

    /// The server is unable to respond to the request because the
    /// domain is on a blocklist as requested by the client.
    /// Functionally, this amounts to "you requested that we filter
    /// domains like this one."
    (Filtered => 17, b"Filtered")

    /// An authoritative server or recursive resolver that receives a
    /// query from an "unauthorized" client can annotate its REFUSED
    /// message with this code. Examples of "unauthorized" clients are
    /// recursive queries from IP addresses outside the network,
    /// blocklisted IP addresses, local policy, etc.
    (Prohibited => 18, b"Prohibited")

    /// The resolver was unable to resolve an answer within its
    /// configured time limits and decided to answer with a previously
    /// cached NXDOMAIN answer instead of answering with an error.
    /// This may be caused, for example, by problems communicating
    /// with an authoritative server, possibly as result of a denial
    /// of service (DoS) attack against another network. (See also
    /// Code 3.)
    (StaleNxdomainAnswer => 19, b"Stale NXDomain Answer")

    /// An authoritative server that receives a query with the
    /// Recursion Desired (RD) bit clear, or when it is not configured
    /// for recursion for a domain for which it is not authoritative,
    /// SHOULD include this EDE code in the REFUSED response. A
    /// resolver that receives a query with the RD bit clear SHOULD
    /// include this EDE code in the REFUSED response.
    (NotAuthoritative => 20, b"Not Authoritative")

    /// The requested operation or query is not supported.
    (NotSupported => 21, b"Not Supported")

    /// The resolver could not reach any of the authoritative name
    /// servers (or they potentially refused to reply).
    (NoReachableAuthority => 22, b"No Reachable Authority")

    /// An unrecoverable error occurred while communicating with
    /// another server.
    (NetworkError => 23, b"Network Error")

    /// The authoritative server cannot answer with data for a zone it
    /// is otherwise configured to support. Examples of this include
    /// its most recent zone being too old or having expired.
    (InvalidData => 24, b"Invalid Data")
}

/// Start of the private range for EDE codes.
///
/// ```text
/// Registration Procedures:
///  o  0     - 49151: First come, first served.
///  o  49152 - 65535: Private use.
/// ```
pub const EDE_PRIVATE_RANGE_BEGIN: u16 = 49152;

// Only implement `Display` for `ExtendedErrorCode`, as the `FromStr`
// bundled by the `int_enum_*` macros is not very useful.
impl core::fmt::Display for ExtendedErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use core::fmt::Write;
        match self.to_mnemonic() {
            Some(m) => {
                for ch in m {
                    f.write_char(*ch as char)?
                }
                Ok(())
            }
            None => write!(f, "EDE{}", self.to_int()),
        }
    }
}
