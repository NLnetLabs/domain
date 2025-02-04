//! ZONEMD IANA parameters.

//------------ ZonemdScheme --------------------------------------------------

int_enum! {
    /// ZONEMD schemes.
    ///
    /// This type selects the method by which data is collated and presented
    /// as input to the hashing function for use with [ZONEMD].
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2024-11-29.
    ///
    /// [ZONEMD]: ../../../rdata/zonemd/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#zonemd-schemes
    =>
    ZonemdScheme, u8;

    /// Specifies that the SIMPLE scheme is used.
    (SIMPLE => 1, "SIMPLE")
}

int_enum_str_decimal!(ZonemdScheme, u8);
int_enum_zonefile_fmt_decimal!(ZonemdScheme, "scheme");

//------------ ZonemdAlg -----------------------------------------------------

int_enum! {
    /// ZONEMD algorithms.
    ///
    /// This type selects the algorithm used to hash domain names for use with
    /// the [ZONEMD].
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2024-11-29.
    ///
    /// [ZONEMD]: ../../../rdata/zonemd/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#zonemd-hash-algorithms
    =>
    ZonemdAlg, u8;

    /// Specifies that the SHA-384 algorithm is used.
    (SHA384 => 1, "SHA384")

    /// Specifies that the SHA-512 algorithm is used.
    (SHA512 => 2, "SHA512")
}

int_enum_str_decimal!(ZonemdAlg, u8);
int_enum_zonefile_fmt_decimal!(ZonemdAlg, "hash algorithm");
