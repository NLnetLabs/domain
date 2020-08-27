//! DNS OpCodes.


//------------ Opcode --------------------------------------------------------

int_enum!{
    /// DNS OpCodes.
    ///
    /// The opcode specifies the kind of query to be performed.
    ///
    /// The opcode and its initial set of values are defined in [RFC 1035].
    /// Additional values have been defined over time. All currently assigned
    /// values can be found in the [IANA registry]. This type is complete as
    /// of 2019-12-23.
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    /// [IANA registry]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
    =>
    Opcode, u8;

    /// A standard query (0).
    ///
    /// This query requests all records matching the name, class, and record
    /// type given in the query’s question section.
    ///
    /// This value is defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (Query => 0, b"QUERY")

    /// An inverse query (IQUERY) (1, obsolete).
    ///
    /// The idea behind inverse queries was to provide a single answer and
    /// ask the DNS for all the questions that would lead to this answer.
    /// This kind of query has always been optional, was never widely
    /// supported, and has therefore been declared obsolete.
    ///
    /// This value was defined in [RFC 1035] and obsoleted by [RFC 3425].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    /// [RFC 3425]: https://tools.ietf.org/html/rfc3425
    (IQuery => 1, b"IQUERY")

    /// A server status request (2).
    ///
    /// This value is defined in [RFC 1035]. The status request itself was
    /// defined as experimental and ‘to be defined’ in [RFC 1034] and seems
    /// to never have been mentioned ever again.
    ///
    /// [RFC 1034]: https://tools.ietf.org/html/rfc1034
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (Status => 2, b"STATUS")

    /// A NOTIFY query (4).
    ///
    /// NOTIFY queries allow primary servers to inform secondary servers when
    /// a zone has changed.
    ///
    /// This value and the NOTIFY query are defined in [RFC 1996].
    ///
    /// [RFC 1996]: https://tools.ietf.org/html/rfc1996
    (Notify => 4, b"NOTIFY")

    /// An UPDATE query (5).
    ///
    /// The UPDATE query can be used to alter zone content managed by an
    /// authoritative server.
    ///
    /// This value and the UPDATE query are defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    (Update => 5, b"UPDATE")

    /// DNS Stateful operations (DSO) (6).
    ///
    /// The DSO query can be used to manage stateful sessions between two
    /// DNS endpoints.
    ///
    /// This value and the DOS query are defined in [RFC 8490].
    ///
    /// [RFC 8490]: https://tools.ietf.org/html/rfc8490
    (Dso => 6, b"DSO")
}

int_enum_str_with_decimal!(Opcode, u8, "unknown opcode");

