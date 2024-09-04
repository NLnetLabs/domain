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
    /// This option was proposed in a draft as a way to state lease times for
    /// registrations made via DNS UPDATE. Its draft, [draft-sekar-dns-ul],
    /// has since expired. The code is considered ‘on hold.’
    ///
    /// [draft-sekar-dns-ul]: http://files.dns-sd.org/draft-sekar-dns-ul.txt
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

    /// DeviceID (26946).
    ///
    /// Ths option is used by the [Cisco Umbrella network device API].
    ///
    /// [Cisco Umbrella network device API]: https://docs.umbrella.com/developer/networkdevices-api/identifying-dns-traffic2
    (DEVICE_ID => 26946, "DeviceId")
}

int_enum_str_with_decimal!(OptionCode, u16, "unknown option code");
int_enum_show_with_decimal!(OptionCode);

//============ Tests =========================================================

#[cfg(test)]
mod test {
    #[cfg(feature = "serde")]
    #[test]
    fn ser_de() {
        use super::OptionCode;
        use serde_test::{assert_tokens, Configure, Token};

        assert_tokens(
            &OptionCode::SERVER_TAG.readable(),
            &[Token::Str("EDNS-Server-Tag")],
        );
        assert_tokens(&OptionCode(10_000).readable(), &[Token::U16(10_000)]);
        assert_tokens(&OptionCode::SERVER_TAG.compact(), &[Token::U16(17)]);
        assert_tokens(&OptionCode(10_000).compact(), &[Token::U16(10_000)]);
    }
}
