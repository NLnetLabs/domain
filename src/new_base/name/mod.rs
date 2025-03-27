//! Domain names.
//!
//! Domain names are a core concept of DNS.  The whole system is essentially
//! just a mapping from domain names to arbitrary information.  This module
//! provides types and essential functionality for working with them.
//!
//! A domain name is a sequence of labels, separated by ASCII periods (`.`).
//! For example, `example.org.` contains three labels: `example`, `org`, and
//! `` (the root label).  Outside DNS-specific code, the root label (and its
//! separator) are almost always omitted, but keep them in mind here.
//!
//! Domain names form a hierarchy, where `b.a` is the "parent" of `.c.b.a`.
//! The owner of `example.org` is thus responsible for _every_ domain ending
//! with the `.example.org` suffix.  The reverse order in which this hierarchy
//! is expressed can sometimes be confusing.

use core::cmp::Ordering;

use super::wire::{BuildBytes, TruncationError};

//--- Submodules

mod label;
pub use label::{Label, LabelBuf, LabelIter};

mod absolute;
pub use absolute::{Name, NameBuf};

mod reversed;
pub use reversed::{RevName, RevNameBuf};

mod unparsed;
pub use unparsed::UnparsedName;

//----------- CanonicalName --------------------------------------------------

/// DNSSEC-conformant operations for domain names.
///
/// As specified by [RFC 4034, section 6], domain names are used in two
/// different ways: they can be serialized into byte strings or compared.
///
/// - In record data, they are serialized following the regular wire format
///   (specifically without name compression).  However, in some record data
///   types, labels are converted to lowercase for serialization.
///
/// - In record owner names, they are compared from the root label outwards,
///   with the contents of each label being compared case-insensitively.
///
/// - In record data, they are compared as serialized byte strings.  As
///   explained above, there are two different valid serializations (i.e. the
///   labels may be lowercased, or the original case may be retained).
///
/// [RFC 4034, section 6]: https://datatracker.ietf.org/doc/html/rfc4034#section-6
///
/// If a domain name type implements [`CanonicalName`], then [`BuildBytes`]
/// will serialize the name in the wire format (without changing the case of
/// its labels).  [`Ord`] will compare domain names as if they were the owner
/// names of records (i.e. not as if they were serialized byte strings).
pub trait CanonicalName: BuildBytes + Ord {
    /// Serialize a domain name with lowercased labels.
    ///
    /// This is subtly different from [`BuildBytes`]; it requires all the
    /// characters in the domain name to be lowercased.  It is implemented
    /// automatically, but it could be overriden for performance.
    fn build_lowercased_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        // Build the bytes as usual.
        let rest = self.build_bytes(bytes)?.len();

        // Find the built bytes and lowercase them.
        let (bytes, rest) = bytes.split_at_mut(rest);
        bytes.make_ascii_lowercase();

        Ok(rest)
    }

    /// Compare domain names as if they were in the wire format.
    ///
    /// This is equivalent to serializing both domain names in the wire format
    /// using [`BuildBytes`] and comparing the resulting byte strings.  It is
    /// implemented automatically, but it could be overriden for performance.
    fn cmp_composed(&self, other: &Self) -> Ordering {
        // Build both names into byte arrays.

        let mut this = [0u8; 255];
        let rest_len = self
            .build_bytes(&mut this)
            .expect("domain names are at most 255 bytes when serialized")
            .len();
        let this = &this[..this.len() - rest_len];

        let mut that = [0u8; 255];
        let rest_len = other
            .build_bytes(&mut that)
            .expect("domain names are at most 255 bytes when serialized")
            .len();
        let that = &that[..that.len() - rest_len];

        // Compare the byte strings.
        this.cmp(that)
    }

    /// Compare domain names as if they were in the wire format, lowercased.
    ///
    /// This is equivalent to serializing both domain names in the wire format
    /// using [`build_lowercased_bytes()`] and comparing the resulting byte
    /// strings.  It is implemented automatically, but it could be overriden
    /// for performance.
    ///
    /// [`build_lowercased_bytes()`]: Self::build_lowercased_bytes()
    fn cmp_lowercase_composed(&self, other: &Self) -> Ordering {
        // Build both names into byte arrays.

        let mut this = [0u8; 255];
        let rest_len = self
            .build_lowercased_bytes(&mut this)
            .expect("domain names are at most 255 bytes when serialized")
            .len();
        let this = &this[..this.len() - rest_len];

        let mut that = [0u8; 255];
        let rest_len = other
            .build_lowercased_bytes(&mut that)
            .expect("domain names are at most 255 bytes when serialized")
            .len();
        let that = &that[..that.len() - rest_len];

        // Compare the byte strings.
        this.cmp(that)
    }
}

impl<N: ?Sized + CanonicalName> CanonicalName for &N {
    fn build_lowercased_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        (**self).build_lowercased_bytes(bytes)
    }

    fn cmp_composed(&self, other: &Self) -> Ordering {
        (**self).cmp_composed(*other)
    }

    fn cmp_lowercase_composed(&self, other: &Self) -> Ordering {
        (**self).cmp_lowercase_composed(*other)
    }
}

impl<N: ?Sized + CanonicalName> CanonicalName for &mut N {
    fn build_lowercased_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        (**self).build_lowercased_bytes(bytes)
    }

    fn cmp_composed(&self, other: &Self) -> Ordering {
        (**self).cmp_composed(*other)
    }

    fn cmp_lowercase_composed(&self, other: &Self) -> Ordering {
        (**self).cmp_lowercase_composed(*other)
    }
}
