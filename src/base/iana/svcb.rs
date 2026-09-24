//! Service Binding (SVCB) Parameter Registry

int_enum! {
    /// DNS SVCB Service Parameter Keys (SvcParamKeys).
    ///
    /// Service Bindings facilitate the lookup of information needed to make
    /// connections to network services.
    ///
    /// For the currently registered values see the [IANA registration].
    /// This type is complete as of the registry update of 2026-06-25.
    ///
    /// [IANA registration]: https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
    =>
    SvcParamKey, u16;

    /// MANDATORY Mandatory keys in this RR.
    ///
    /// See [RFC9460, Section 8].
    ///
    /// [RFC9460, Section 8]: https://datatracker.ietf.org/doc/html/rfc9460#name-servicemode-rr-compatibilit
    (MANDATORY => 0, "mandatory")

    /// ALPN Additional supported protocols.
    ///
    /// See [RFC9460, Section 7.1].
    ///
    /// [RFC9460, Section 7.1]: https://datatracker.ietf.org/doc/html/rfc9460#name-alpn-and-no-default-alpn
    (ALPN => 1, "alpn")

    /// NO-DEFAULT-ALPN No support for default protocol.
    ///
    /// See [RFC9460, Section 7.1].
    ///
    /// [RFC9460, Section 7.1]: https://datatracker.ietf.org/doc/html/rfc9460#name-alpn-and-no-default-alpn
    (NO_DEFAULT_ALPN => 2, "no-default-alpn")

    /// PORT Port for alternative endpoint.
    ///
    /// See [RFC9460, Section 7.2].
    ///
    /// [RFC9460, Section 7.2]: https://datatracker.ietf.org/doc/html/rfc9460#name-port
    (PORT => 3, "port")

    /// IPV4HINT IPv4 address hints.
    ///
    /// See [RFC9460, Section 7.3].
    ///
    /// [RFC9460, Section 7.3]: https://datatracker.ietf.org/doc/html/rfc9460#name-ipv4hint-and-ipv6hint
    (IPV4HINT => 4, "ipv4hint")

    /// ECH TLS Encrypted ClientHello Config.
    ///
    /// See [RFC9848].
    ///
    /// [RFC9848]: https://datatracker.ietf.org/doc/html/rfc9848
    (ECH => 5, "ech")

    /// IPV6HINT IPv6 address hints.
    ///
    /// See [RFC9460, Section 7.3].
    ///
    /// [RFC9460, Section 7.3]: https://datatracker.ietf.org/doc/html/rfc9460#name-ipv4hint-and-ipv6hint
    (IPV6HINT => 6, "ipv6hint")

    /// DOHPATH DNS over HTTPS path template.
    ///
    /// See [RFC9461].
    ///
    /// [RFC9461]: https://datatracker.ietf.org/doc/html/rfc9461
    (DOHPATH => 7, "dohpath")

    /// OHTTP Denotes that a service operates an Oblivious HTTP target.
    ///
    /// See [RFC9461].
    ///
    /// [RFC9461]: https://datatracker.ietf.org/doc/html/rfc9461
    (OHTTP => 8, "ohttp")

    /// TLS-SUPPORTED-GROUPS Supported groups in TLS.
    ///
    /// See [draft-ietf-tls-key-share-prediction].
    ///
    /// [draft-ietf-tls-key-share-prediction]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-key-share-prediction
    (TLS_SUPPORTED_GROUPS => 9, "tls-supported-groups")

    /// DOCPATH DNS over CoAP resource path.
    ///
    /// See [RFC9953].
    ///
    /// [RFC9953]: https://datatracker.ietf.org/doc/html/rfc9953#name-selection-of-a-doc-server
    (DOCPATH => 10, "docpath")

    /// PVD PvD configuration is available at the well-known path.
    ///
    /// See [draft-ietf-intarea-proxy-config].
    ///
    /// [draft-ietf-intarea-proxy-config]: https://datatracker.ietf.org/doc/html/draft-ietf-intarea-proxy-config#section-2.1
    (PVD => 11, "pvd")

    /// OOTS Per-transport operator confidence in serving the nameserver's
    /// query load over that transport, as a percentage.
    ///
    /// See [draft-johani-dnsop-svcb-oots].
    ///
    /// [draft-johani-dnsop-svcb-oots]: https://datatracker.ietf.org/doc/html/draft-johani-dnsop-svcb-oots#section-5
    (OOTS => 12, "oots")
}

int_enum_str_with_prefix!(SvcParamKey, "key", b"key", u16, "unknown key");
int_enum_zonefile_fmt_with_prefix!(SvcParamKey, "key");

impl SvcParamKey {
    pub const PRIVATE_RANGE_BEGIN: u16 = 65280;
    pub const PRIVATE_RANGE_END: u16 = 65534;
    pub const INVALID: Self = Self(65535);
}
