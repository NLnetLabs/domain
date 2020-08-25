//! Additional traits for comparisions.
//!
//! These traits exist because there are several ways of compare domain
//! names included in composite structures. Normally, names are compared
//! ignoring ASCII case. This is what `PartialEq` and `PartialOrd` do for
//! domain names. Consequently, when comparing resource records and record
//! data that contain domain names, ASCII case should also be ignored.
//!
//! However, the canonical form of most resource type’s record data (apart
//! from a small set of well-known types) requires names to be considered
//! as they are for comparisons. In order to make it clear when this mode
//! of comparision is used, this module defines a new trait [`CanonicalOrd`]
//! that allows types to define how they should be compared in the context of
//! DNSSEC. The trait is accompanied by [`Compose::compose_canonical`] which
//! produces the canonical form of this data.
//!
//! [`CanonicalOrd`]: trait.CanonicalOrd.html
//! [`Compose::compose_canonical`]: ../octets/trait.Compose.html#method.compose_canonical

use core::cmp::Ordering;


/// A trait for the canonical sort order of values.
///
/// The canonical sort order is used in DNS security when multiple values are
/// part of constructing or validating a signature. This sort order differs
/// in some cases from the normal sort order. To avoid confusion, only this
/// trait should be used when DNSSEC signatures are involved.
///
/// Canonical order is defined in [RFC 4034] and clarified in [RFC 6840]. It
/// is defined for domain names and resource records within an RR set (i.e.,
/// a set of records with the same owner name, class, and type).
///
/// For domain names, canonical order is the same as the ‘normal’ order as
/// implemented through the `PartialOrd` and `Ord` traits: Labels are compared
/// from right to left (i.e, starting from the root label) with each pair of
/// labels compared as octet sequences with ASCII letters lowercased
/// before comparison.  The `name_cmp` methods of the `ToDname` and
/// `ToRelativeDname` traits can be used to implement this canonical order
/// for name types.
///
/// Resource records within an RR set are ordered by comparing the canonical
/// wire-format representation of their record data as octet sequences. The
/// canonical form differs from the regular form by lower-casing domain names
/// included in the record data for the record types NS, MD, MF, CNAME, SOA,
/// MB, MG, MR, PTR, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV,
/// DNAME, A6, and RRSIG. (NSEC is listed in [RFC 4034] but has been withdrawn
/// by [RFC 6840]). This canonical representation is provided via the
/// `Compose::compose_canonical` method.
///
/// In order to help implementing this trait for record data types, there are
/// implementations of it for some types that can appear in record data that
/// sort differently in their composed representation than normally.
///
/// Apart from these explicit use cases, the `CanonicalOrd` trait is also
/// implemented for the `Record` type to allow ordering records of a zone into
/// RRsets. It does so by ordering by class first, then canonical owner,
/// record type, and finally canonical record data. The reason for this
/// somewhat odd ordering is that in this way not only are all records
/// for the same owner name and class kept together, but also all the records
/// subordinate to a owner name and class pair (i.e., the records for a zone)
/// will sort together.
///
/// [RFC 4034]: https://tools.ietf.org/html/rfc4034
/// [RFC 6840]: https://tools.ietf.org/html/rfc6840
pub trait CanonicalOrd<Rhs: ?Sized = Self> {
    /// Returns the canonical ordering between `self` and `other`.
    #[must_use]
    fn canonical_cmp(&self, other: &Rhs) -> Ordering;

    /// Returns whether `self` is canonically less than `other`.
    #[inline]
    #[must_use]
    fn canonical_lt(&self, other: &Rhs) -> bool {
        match self.canonical_cmp(other) {
            Ordering::Less => true,
            _ => false,
        }
    }

    /// Returns whether `self` is canonically less than or equal to `other`.
    #[inline]
    #[must_use]
    fn canonical_le(&self, other: &Rhs) -> bool {
        match self.canonical_cmp(other) {
            Ordering::Less | Ordering::Equal => true,
            _ => false,
        }
    }

    /// Returns whether `self` is canonically greater than `other`.
    #[inline]
    #[must_use]
    fn canonical_gt(&self, other: &Rhs) -> bool {
        match self.canonical_cmp(other) {
            Ordering::Greater => true,
            _ => false,
        }
    }

    /// Returns whether `self` is canonically greater than or equal to `other`.
    #[inline]
    #[must_use]
    fn canonical_ge(&self, other: &Rhs) -> bool {
        match self.canonical_cmp(other) {
            Ordering::Greater | Ordering::Equal => true,
            _ => false,
        }
    }
}

