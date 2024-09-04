//! DNS CLASSes.

//------------ Class ---------------------------------------------------------

int_enum! {
    /// DNS CLASSes.
    ///
    /// The domain name space is partitioned into separate classes for different
    /// network types. That is, each class has its own separate record tree
    /// starting at the root. However, in practice, only the IN class is really
    /// relevant.
    ///
    /// In addition, there are query classes or QCLASSes that are used in
    /// questions or UPDATE queries, namely NONE and ANY (or *).
    ///
    /// Classes are represented by a 16 bit value. The enum wraps these values.
    ///
    /// See [RFC 1034] for the introduction of classes, section 3.2 of
    /// [RFC 6895] for a discussion of the current state of afairs, and
    /// the [DNS CLASSes IANA registry] for an overview of assigned values.
    /// This type is complete as of the registry update of 2019-01-28.
    ///
    /// [RFC 1034]: https://tools.ietf.org/html/rfc1034
    /// [RFC 6895]: https://tools.ietf.org/html/rfc6895
    /// [DNS CLASSes IANA registry]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
    =>
    Class, u16;

    /// Internet (IN).
    ///
    /// This class is defined in RFC 1035 and really the only one relevant
    /// at all.
    (IN => 1, "IN")

    /// Chaosnet (CH).
    ///
    /// A network protocol developed at MIT in the 1970s. Reused by BIND for
    /// built-in server information zones.",
    (CH => 3, "CH")

    /// Hesiod (HS).
    ///
    /// A system information protocol part of MIT's Project Athena.",
    (HS => 4, "HS")

    /// Query class None.
    ///
    /// Defined in RFC 2136, this class is used in UPDATE queries to
    /// require that an RRset does not exist prior to the update.",
    (NONE => 0xFE, "NONE")

    /// Query class * (ANY).
    ///
    /// This class can be used in a query to indicate that records for the
    /// given name from any class are requested.",
    (ANY => 0xFF, "*")
}

int_enum_str_with_prefix!(Class, "CLASS", b"CLASS", u16, "unknown class");
int_enum_show_with_prefix!(Class, "CLASS");

//============ Tests =========================================================

#[cfg(test)]
mod test {

    #[cfg(feature = "serde")]
    #[test]
    fn ser_de() {
        use super::Class;
        use serde_test::{assert_tokens, Configure, Token};

        assert_tokens(&Class::IN.readable(), &[Token::Str("IN")]);
        assert_tokens(&Class(5).readable(), &[Token::Str("CLASS5")]);
        assert_tokens(&Class::IN.compact(), &[Token::U16(1)]);
        assert_tokens(&Class(5).compact(), &[Token::U16(5)]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn debug() {
        use super::Class;

        assert_eq!(format!("{:?}", Class::IN), "Class::IN");
        assert_eq!(format!("{:?}", Class(69)), "Class(69)");
    }
}
