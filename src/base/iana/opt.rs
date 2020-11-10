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
    (Llq => 1, b"LLQ")

    /// Update lease (UL, 2).
    ///
    /// This option was proposed in a draft as a way to state lease times for
    /// registrations made via DNS UPDATE. Its draft, [draft-sekar-dns-ul],
    /// has since expired. The code is considered ‘on hold.’
    ///
    /// [draft-sekar-dns-ul]: http://files.dns-sd.org/draft-sekar-dns-ul.txt
    (Ul => 2, b"UL")

    /// Name server identifier (NSID, 3).
    ///
    /// The NSID option allows a name server to include an indentifier in an
    /// answer for diagnostic purposes. The options in defined in [RFC 5001].
    ///
    /// [RFC 5001]: https://tools.ietf.org/html/rfc5001
    (Nsid => 3, b"NSID")

    /// DNSSEC algorithm understood (DAU, 5).
    ///
    /// The DAU option allows a validating resolver to signal a queried server
    /// which DNSSEC signing algorithms it understands. The option is defined
    /// in [RFC 6975].
    ///
    /// [RFC 6075]: https://tools.ietf.org/html/rfc6975
    (Dau => 5, b"DAU")

    /// DS hash understood (DHU, 6).
    ///
    /// The DHU option allows a validating resolver to signal a queried server
    /// which DS hash algorithms it understands. The option is defined
    /// in [RFC 6975].
    ///
    /// [RFC 6075]: https://tools.ietf.org/html/rfc6975
    (Dhu => 6, b"DHU")

    /// NSEC3 hash understood (N3U, 7).
    ///
    /// The DHU option allows a validating resolver to signal a queried server
    /// which NSEC3 hash algorithms it understands. The option is defined
    /// in [RFC 6975].
    ///
    /// [RFC 6075]: https://tools.ietf.org/html/rfc6975
    (N3u => 7, b"N3U")

    /// EDNS client subnet (8),
    ///
    /// The EDSN client subnet option allows a resolver to identify the IP
    /// address subnet it queries from so that a server can determine the best
    /// answer. This option is defined in [RFC 7871].
    ///
    /// [RFC 7871]: https://tools.ietf.org/html/rfc7871
    (ClientSubnet => 8, b"edns-client-subnet")

    /// Expire (9).
    ///
    /// The expire option allows a secondary to maintain the correct expiry
    /// time for a zone when transferring from a server other than the
    /// primary. The option is defined in [RFC 7314].
    ///
    /// [RFC 7314]: https://tools.ietf.org/html/rfc7314
    (Expire => 9, b"EDNS EXPIRE")

    /// DNS Cookie (10).
    ///
    /// The cookie option allows clients and server to exchange session
    /// cookies as a mechanism for protecting agains denial-of-service and
    /// amplification attacks. The option is defined in [RFC 7873].
    ///
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    (Cookie => 10, b"COOKIE")

    /// edns-tcp-keepalive (11).
    ///
    /// This option allows DNS servers to signal to a client for how long they
    /// may hold open a TCP connection. The option is defined in [RFC 7828].
    ///
    /// [RFC 7828]: https://tools.ietf.org/html/rfc7828
    (TcpKeepalive => 11, b"edns-tcp-keepalive")

    /// Padding (12).
    ///
    /// The padding option allows clients and servers to pad their messages
    /// with extra data to make it harder to guess content based on length.
    /// The option is defined in [RFC 7830].
    ///
    /// [RFC 7830]: https://tools.ietf.org/html/rfc7830
    (Padding => 12, b"Padding")

    /// CHAIN query requests (13).
    ///
    /// The CHAIN query requests option allows a security-aware resolver to
    /// all ask a server to include records necessary for DNSSEC validation of
    /// the answer. The option is defined in [RFC 7901].
    ///
    /// [RFC 7901]: https://tools.ietf.org/html/rfc7901
    (Chain => 13, b"CHAIN")

    /// EDNS key tag (14).
    ///
    /// The key tag option allows a client to signal to a server which DNSSEC
    /// key they would use to validate an asnwer. The option is defined in
    /// [RFC 8145].
    ///
    /// [RFC 8145]: https://tools.ietf.org/html/rfc8145
    (KeyTag => 14, b"edns-key-tag")

    /// Extended DNS Error (15).
    ///
    /// This option allows the server to return additional information
    /// about the cause of DNS errors. It does not change the
    /// processing of RCODEs. The option is defined in [RFC 8914].
    ///
    /// [RFC 8914]: https://tools.ietf.org/html/rfc8914
    (ExtendedError => 15, b"Extended DNS Error")

    /// EDNS client tag (16).
    ///
    /// The client tag option allows a client to send arbitrary additional
    /// data to a server. The option is defined in the now expired
    /// [draft-bellis-dnsop-edns-tags].
    ///
    /// [draft-bellis-dnsop-edns-tags]: https://datatracker.ietf.org/doc/draft-bellis-dnsop-edns-tags/
    (ClientTag => 16, b"EDNS-Client-Tag")

    /// EDNS server tag (16).
    ///
    /// The client tag option allows a server to send arbitrary additional
    /// data to a client. The option is defined in the now expired
    /// [draft-bellis-dnsop-edns-tags].
    ///
    /// [draft-bellis-dnsop-edns-tags]: https://datatracker.ietf.org/doc/draft-bellis-dnsop-edns-tags/
    (ServerTag => 17, b"EDNS-Server-Tag")

    /// DeviceID (26946).
    ///
    /// Ths option is used by the [Cisco Umbrella network device API].
    ///
    /// [Cisco Umbrella network device API]: https://docs.umbrella.com/developer/networkdevices-api/identifying-dns-traffic2
    (DeviceId => 26946, b"DeviceId")
}

int_enum_str_with_decimal!(OptionCode, u16, "unknown option code");

