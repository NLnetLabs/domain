//! DNS EDNS0 pption codes.

//------------ OptionCode ----------------------------------------------------

int_enum! {
    /// DNS EDNS0 option codes.
    ///
    /// The record data of [OPT] records is a sequence of options. The type of
    /// each of these options is given through a 16 bit value called *option
    /// code.*
    ///
    /// The currently assigned option codes can be found in the
    /// [IANA registry]. The type is complete as of 2019-12-23.
    ///
    /// [OPT]: ../../opt/index.html
    /// [IANA registry]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
    =>
    OptionCode, u16;

    /// Long-Lived Queries (LLQ, 1).
    ///
    /// Long-Lived Queries is a protocol developed by Apple for change
    /// notifications. It is now being replaced by DNS Push Notifications.
    /// The LLQ options is used in LLQ messages.
    ///
    /// This option code and the LLQ option are defined in a upcoming RFC,
    /// currently [draft-sekar-dns-llq].
    ///
    /// [draft-sekar-dns-llq]: https://datatracker.ietf.org/doc/draft-sekar-dns-llq/
    (LLQ => 1, "LLQ")

    /// Update lease (UL, 2).
    ///
    /// This option is used to request lease times for registrations made via
    /// DNS UPDATE. DNS lease expiration is used in the DNS-SD Service
    /// Registration Protocol [RFC 9665]. The option is defined in [RFC 9664].
    ///
    /// [RFC 9664]: https://datatracker.ietf.org/doc/html/rfc9664
    /// [RFC 9665]: https://datatracker.ietf.org/doc/html/rfc9665
    (UL => 2, "UL")

    /// Name server identifier (NSID, 3).
    ///
    /// The NSID option allows a name server to include an indentifier in an
    /// answer for diagnostic purposes. The options in defined in [RFC 5001].
    ///
    /// [RFC 5001]: https://tools.ietf.org/html/rfc5001
    (NSID => 3, "NSID")

    /// DNSSEC algorithm understood (DAU, 5).
    ///
    /// The DAU option allows a validating resolver to signal a queried server
    /// which DNSSEC signing algorithms it understands. The option is defined
    /// in [RFC 6975].
    ///
    /// [RFC 6075]: https://tools.ietf.org/html/rfc6975
    (DAU => 5, "DAU")

    /// DS hash understood (DHU, 6).
    ///
    /// The DHU option allows a validating resolver to signal a queried server
    /// which DS hash algorithms it understands. The option is defined
    /// in [RFC 6975].
    ///
    /// [RFC 6075]: https://tools.ietf.org/html/rfc6975
    (DHU => 6, "DHU")

    /// NSEC3 hash understood (N3U, 7).
    ///
    /// The DHU option allows a validating resolver to signal a queried server
    /// which NSEC3 hash algorithms it understands. The option is defined
    /// in [RFC 6975].
    ///
    /// [RFC 6075]: https://tools.ietf.org/html/rfc6975
    (N3U => 7, "N3U")

    /// EDNS client subnet (8),
    ///
    /// The EDSN client subnet option allows a resolver to identify the IP
    /// address subnet it queries from so that a server can determine the best
    /// answer. This option is defined in [RFC 7871].
    ///
    /// [RFC 7871]: https://tools.ietf.org/html/rfc7871
    (CLIENT_SUBNET => 8, "edns-client-subnet")

    /// Expire (9).
    ///
    /// The expire option allows a secondary to maintain the correct expiry
    /// time for a zone when transferring from a server other than the
    /// primary. The option is defined in [RFC 7314].
    ///
    /// [RFC 7314]: https://tools.ietf.org/html/rfc7314
    (EXPIRE => 9, "EDNS EXPIRE")

    /// DNS Cookie (10).
    ///
    /// The cookie option allows clients and server to exchange session
    /// cookies as a mechanism for protecting agains denial-of-service and
    /// amplification attacks. The option is defined in [RFC 7873].
    ///
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    (COOKIE => 10, "COOKIE")

    /// edns-tcp-keepalive (11).
    ///
    /// This option allows DNS servers to signal to a client for how long they
    /// may hold open a TCP connection. The option is defined in [RFC 7828].
    ///
    /// [RFC 7828]: https://tools.ietf.org/html/rfc7828
    (TCP_KEEPALIVE => 11, "edns-tcp-keepalive")

    /// Padding (12).
    ///
    /// The padding option allows clients and servers to pad their messages
    /// with extra data to make it harder to guess content based on length.
    /// The option is defined in [RFC 7830].
    ///
    /// [RFC 7830]: https://tools.ietf.org/html/rfc7830
    (PADDING => 12, "Padding")

    /// CHAIN query requests (13).
    ///
    /// The CHAIN query requests option allows a security-aware resolver to
    /// all ask a server to include records necessary for DNSSEC validation of
    /// the answer. The option is defined in [RFC 7901].
    ///
    /// [RFC 7901]: https://tools.ietf.org/html/rfc7901
    (CHAIN => 13, "CHAIN")

    /// EDNS key tag (14).
    ///
    /// The key tag option allows a client to signal to a server which DNSSEC
    /// key they would use to validate an asnwer. The option is defined in
    /// [RFC 8145].
    ///
    /// [RFC 8145]: https://tools.ietf.org/html/rfc8145
    (KEY_TAG => 14, "edns-key-tag")

    /// Extended DNS Error (15).
    ///
    /// This option allows the server to return additional information
    /// about the cause of DNS errors. It does not change the
    /// processing of RCODEs. The option is defined in [RFC 8914].
    ///
    /// [RFC 8914]: https://tools.ietf.org/html/rfc8914
    (EXTENDED_ERROR => 15, "Extended DNS Error")

    /// EDNS client tag (16).
    ///
    /// The client tag option allows a client to send arbitrary additional
    /// data to a server. The option is defined in the now expired
    /// [draft-bellis-dnsop-edns-tags].
    ///
    /// [draft-bellis-dnsop-edns-tags]: https://datatracker.ietf.org/doc/draft-bellis-dnsop-edns-tags/
    (CLIENT_TAG => 16, "EDNS-Client-Tag")

    /// EDNS server tag (16).
    ///
    /// The client tag option allows a server to send arbitrary additional
    /// data to a client. The option is defined in the now expired
    /// [draft-bellis-dnsop-edns-tags].
    ///
    /// [draft-bellis-dnsop-edns-tags]: https://datatracker.ietf.org/doc/draft-bellis-dnsop-edns-tags/
    (SERVER_TAG => 17, "EDNS-Server-Tag")

    /// Report-Channel (18).
    ///
    /// DNS error reporting is a lightweight reporting mechanism that provides
    /// the operator of an authoritative server with reports on DNS resource
    /// records that fail to resolve or validate. Defined in [RFC9567].
    ///
    /// [RFC9567]: https://datatracker.ietf.org/doc/html/rfc9567
    (REPORT_CHANNEL => 18, "Report-Channel")

    /// ZONEVERSION (19).
    ///
    /// The DNS ZONEVERSION option is a way for DNS clients to request, and
    /// for authoritative DNS servers to provide, information regarding the
    /// version of the zone from which a response is generated. Defined in
    /// [RFC9660].
    ///
    /// [RFC9660]: https://datatracker.ietf.org/doc/html/rfc9660
    (ZONEVERSION => 19, "ZONEVERSION")

    /// MQTYPE-Query (20).
    ///
    /// Client to request additional DNS record types to be delivered
    /// alongside the primary record type specified in the question section of
    /// a DNS QUERY (OpCode=0). Defined in [RFC-ietf-dnssd-multi-qtypes].
    ///
    /// [RFC-ietf-dnssd-multi-qtypes]: https://datatracker.ietf.org/doc/html/draft-ietf-dnssd-multi-qtypes
    (MQTYPE_QUERY => 20, "MQTYPE-Query")

    /// MQTYPE-Response (21).
    ///
    /// Server to respond with additional DNS records delivered alongside the
    /// primary record type specified in the question section of a DNS QUERY
    /// (OpCode=0). Defined in [RFC-ietf-dnssd-multi-qtypes].
    ///
    /// [RFC-ietf-dnssd-multi-qtypes]: https://datatracker.ietf.org/doc/html/draft-ietf-dnssd-multi-qtypes
    (MQTYPE_RESPONSE => 21, "MQTYPE-Response")

    /// EDE-EXTRA-TEXT-LANGUAGE (22).
    ///
    /// This option specifies the language that is used in the EXTRA-TEXT
    /// field of EDNS Extended DNS Error options in the same DNS message.
    /// Defined in [draft-muks-dns-filtering].
    ///
    /// [draft-muks-dns-filtering]: https://datatracker.ietf.org/doc/html/draft-muks-dns-filtering#name-ede-extra-text-language-edn
    (EDE_EXTRA_TEXT_LANGUAGE => 22, "EDE-EXTRA-TEXT-LANGUAGE")

    /// FILTERING-CONTACT (23).
    ///
    /// When DNS queries cause filtering to be performed by nameservers and
    /// negative responses to be returned due to it, the nameserver MAY return
    /// zero or more FILTERING-CONTACT EDNS options in responses, containing
    /// contact information of the party that performed the filtering.
    /// Defined in [draft-muks-dns-filtering].
    ///
    /// [draft-muks-dns-filtering]: https://datatracker.ietf.org/doc/html/draft-muks-dns-filtering#name-filtering-contact-edns-opti
    (FILTERING_CONTACT => 23, "FILTERING-CONTACT")

    /// FILTERING-ORGANIZATION (24).
    ///
    /// When DNS queries cause filtering to be performed by nameservers and
    /// negative responses to be returned due to it, the nameserver MAY return
    /// zero or one FILTERING-ORGANIZATION EDNS option in responses,
    /// containing the name of the organization that performed the filtering.
    /// Defined in [draft-muks-dns-filtering].
    ///
    /// [draft-muks-dns-filtering]: https://datatracker.ietf.org/doc/html/draft-muks-dns-filtering#name-filtering-organization-edns
    (FILTERING_ORGANIZATION => 24, "FILTERING-ORGANIZATION")

    /// FILTERING-DB (25).
    ///
    /// When DNS queries cause filtering to be performed by nameservers and
    /// negative responses to be returned due to it, the nameserver MAY return
    /// zero or one FILTERING-DB EDNS option in responses, containing the
    /// identifier, name, or description of the filtering database against
    /// which a matched query caused the filtering to occur.
    /// Defined in [draft-muks-dns-filtering].
    ///
    /// [draft-muks-dns-filtering]: https://datatracker.ietf.org/doc/html/draft-muks-dns-filtering#name-filtering-db-edns-option
    (FILTERING_DB => 25, "FILTERING-DB")

    /// Umbrella Ident (20292).
    ///
    /// Ths option is used by the [Cisco Umbrella network device API].
    ///
    /// [Cisco Umbrella network device API]: https://developer.cisco.com/docs/cloud-security/network-devices-with-cisco-umbrella-dns/#network-devices-with-cisco-umbrella-dns
    (UMBRELLA_IDENT => 20292, "Umbrella Ident")

    /// DeviceID (26946).
    ///
    /// This option is used by the [Cisco Umbrella network device API].
    ///
    /// [Cisco Umbrella network device API]: https://developer.cisco.com/docs/cloud-security/network-devices-with-cisco-umbrella-dns/#network-devices-with-cisco-umbrella-dns
    (DEVICE_ID => 26946, "DeviceId")
}

int_enum_str_with_decimal!(OptionCode, u16, "unknown option code");
int_enum_zonefile_fmt_with_decimal!(OptionCode);

//============ Tests =========================================================

#[cfg(test)]
mod test {
    #[cfg(feature = "serde")]
    #[test]
    fn ser_de() {
        use super::OptionCode;
        use serde_test::{Configure, Token, assert_tokens};

        assert_tokens(
            &OptionCode::SERVER_TAG.readable(),
            &[Token::Str("EDNS-Server-Tag")],
        );
        assert_tokens(&OptionCode(10_000).readable(), &[Token::U16(10_000)]);
        assert_tokens(&OptionCode::SERVER_TAG.compact(), &[Token::U16(17)]);
        assert_tokens(&OptionCode(10_000).compact(), &[Token::U16(10_000)]);
    }
}
