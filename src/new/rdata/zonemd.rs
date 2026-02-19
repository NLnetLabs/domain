//! The ZONEMD record type.
//!
//! See [RFC 8976](https://www.rfc-editor.org/rfc/rfc8976.html).

use core::{cmp::Ordering, fmt};

use crate::{
    new::base::{
        build::BuildInMessage,
        name::NameCompressor,
        wire::{
            AsBytes, BuildBytes, ParseBytes, ParseBytesZC, ParseError,
            SplitBytes, SplitBytesZC, TruncationError,
        },
        CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
        Serial,
    },
    utils::dst::UnsizedCopy,
};

//----------- ZoneMD ---------------------------------------------------------

/// A message digest of the enclosing zone.
///
/// A [`ZoneMD`] record contains a deterministically computed digest (i.e.
/// cryptographic hash) of the contents of the surrounding zone. It can
/// be used to verify the integrity (and possibly authenticity) of all the
/// records in the zone, including glue records, even at rest.
///
/// [`ZoneMD`] is specified by [RFC 8976]. As discussed within, it provides
/// unique functionality over other means of checking and authenticating DNS
/// zones; when DNSSEC-signed, it asserts the authenticity of glue records
/// present with the zone. This is especially important for the root zone.
///
/// [RFC 8976]: https://www.rfc-editor.org/rfc/rfc8976.html
///
/// ## Computation
///
/// [`ZoneMD`] specifies a [scheme] and a [hash algorithm]. The scheme decides
/// how the records in the zone will be collected, serialized, and hashed. The
/// hash algorithm simply selects a cryptographic hash function. The scheme
/// and hash algorithm are completely independent selections; at present,
/// there are no (overt or subtle) interactions hindering certain combinations
/// of scheme and hash algorithm.
///
/// [scheme]: ZoneMDScheme
/// [hash algorithm]: ZoneMDHashAlg
///
/// At present, [`ZoneMD`] has some drawbacks. The defined schemes do not
/// support parallelization or incrementality, so arbitrarily small changes
/// to the zone require re-computing the digest (effectively) from scratch.
/// While this is acceptable for smaller zones, it hinders usage in larger
/// zones (primarily TLDs). New algorithms may be defined in the future which
/// provide parallelization and incrementality without loss of security.
///
/// ## Wire Format
///
/// The wire format of a [`ZoneMD`] record is the concatenation of its fields,
/// in the same order as the `struct` definition.
///
/// The memory layout of the [`ZoneMD`] type is identical to its serialization
/// in the wire format. This means it can be parsed from the wire format in a
/// zero-copy fashion, which is more efficient.
///
/// ## Usage
///
/// Because [`ZoneMD`] is a record data type, it is usually handled within
/// an enum like [`RecordData`]. This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// By default, [`ZoneMD`] is a _dynamically sized type_ (DST). It is not
/// possible to store a [`ZoneMD`] in place (e.g. in a local variable); it
/// must be held indirectly, via a reference or a smart pointer type like
/// [`Box`].
///
/// [`Box`]: https://doc.rust-lang.org/std/boxed/struct.Box.html
///
/// However, [`ZoneMD`] _can_ be constructed in place by taking advantage of
/// its generic parameter. Just as you can define a `[u8; 48]` in a local
/// variable, then hold it by reference as a `&[u8]`, you can define a
/// `ZoneMD<[u8; 48]>` in a local variable, then hold it by reference as a
/// `&ZoneMD<[u8]>`. `[u8]` is the default for that generic parameter.
///
/// There's a few ways to build a [`ZoneMD`]:
///
/// ```
/// # use domain::new::base::wire::{ParseBytes, ParseBytesZC, BuildBytes};
/// # use domain::new::rdata::{ZoneMD, ZoneMDScheme, ZoneMDHashAlg};
/// #
/// // Construct a 'ZoneMD' directly:
/// let direct: ZoneMD<[u8; 48]> = ZoneMD {
///     serial: 42.into(),
///     scheme: ZoneMDScheme::SIMPLE,
///     hash_alg: ZoneMDHashAlg::SHA384,
///     digest: [
///         0xb9, 0x10, 0xcb, 0xc5, 0x64, 0xfa, 0x4d, 0x47,
///         0x52, 0xde, 0x22, 0x31, 0x27, 0x4a, 0x42, 0xcc,
///         0xfd, 0x3d, 0x88, 0xde, 0x1c, 0x16, 0x4b, 0xfa,
///         0xc2, 0x61, 0x20, 0x32, 0x30, 0x01, 0x48, 0xa9,
///         0x7e, 0x73, 0x00, 0x4a, 0x63, 0x6f, 0x0e, 0xa5,
///         0xfc, 0x17, 0xe6, 0xbe, 0x74, 0x8f, 0x3f, 0x2a,
///     ],
/// };
/// // Taken by reference, the generic parameter can be dropped.
/// // This is an unsizing coercion to 'ZoneMD<[u8]>'.
/// let direct: &ZoneMD = &direct;
///
/// // Parse a 'ZoneMD' from the DNS wire format:
/// let bytes = [
///     0, 0, 0, 42, 1, 1,
///     0xb9, 0x10, 0xcb, 0xc5, 0x64, 0xfa, 0x4d, 0x47,
///     0x52, 0xde, 0x22, 0x31, 0x27, 0x4a, 0x42, 0xcc,
///     0xfd, 0x3d, 0x88, 0xde, 0x1c, 0x16, 0x4b, 0xfa,
///     0xc2, 0x61, 0x20, 0x32, 0x30, 0x01, 0x48, 0xa9,
///     0x7e, 0x73, 0x00, 0x4a, 0x63, 0x6f, 0x0e, 0xa5,
///     0xfc, 0x17, 0xe6, 0xbe, 0x74, 0x8f, 0x3f, 0x2a,
/// ];
/// let from_bytes = ZoneMD::parse_bytes_by_ref(&bytes).unwrap();
/// // It is also possible to use '<&ZoneMD>::parse_bytes()'.
/// # assert_eq!(from_bytes, direct);
///
/// // Serialize a 'ZoneMD' in the DNS wire format:
/// let mut buffer = vec![0u8; from_bytes.built_bytes_size()];
/// from_bytes.build_bytes(&mut buffer).unwrap();
/// assert_eq!(buffer, bytes);
///
/// // Parse a 'ZoneMD' from the wire format, but on the heap:
/// let buffer: Box<[u8]> = buffer.into_boxed_slice();
/// let from_boxed_bytes: Box<ZoneMD> = ZoneMD::parse_bytes_in(buffer).unwrap();
/// assert_eq!(from_bytes, &*from_boxed_bytes);
/// ```
///
/// [`ZoneMD`] implements [`Copy`], [`Clone`], and/or [`UnsizedCopy`] if
/// its digest type implements them. By default, its digest type is `[u8]`,
/// which only implements [`UnsizedCopy`]. A `&ZoneMD` can be copied into a
/// different container (e.g. `Box`) using [`unsized_copy_into()`].
///
/// [`unsized_copy_into()`]: UnsizedCopy::unsized_copy_into()
///
/// For debugging, [`ZoneMD`] can be formatted using [`fmt::Debug`].
///
/// To serialize a [`ZoneMD`] in the wire format, use [`BuildBytes`]
/// (which will serialize it to a given buffer) or [`AsBytes`] (which will
/// cast the [`ZoneMD`] into a byte sequence in place). It also supports
/// [`BuildInMessage`].
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesZC,
    UnsizedCopy,
)]
#[repr(C)]
pub struct ZoneMD<Digest: ?Sized = [u8]> {
    /// The associated SOA serial number.
    ///
    /// The [`ZoneMD`] is specifically associated with the instance of the
    /// DNS zone that has this serial number in its SOA record (i.e. in
    /// [`Soa::serial`]). When performing ZONEMD verification, this field
    /// must be checked for consistency with the actual SOA record.
    ///
    /// [`Soa::serial`]: crate::new::rdata::Soa::serial
    ///
    /// In case a ZONEMD verification failure occurs, an inconsistency in this
    /// field indicates that the ZONEMD record might simply be out-of-date.
    /// This can be used for diagnostics, but must not be used to infer
    /// anything about the integrity or authenticity of the zone.
    pub serial: Serial,

    /// The scheme used to compute the digest.
    ///
    /// This field "identifies the methods by which data is collated and
    /// presented as input to the hashing function". It is independent of
    /// the hash algorithm, which is specified separately.
    pub scheme: ZoneMDScheme,

    /// The hash algorithm used.
    ///
    /// This field "identifies the cryptographic hash algorithm used to
    /// construct the digest". It is independent of the scheme, which dictates
    /// how the hash algorithm is used, and is specified separately.
    pub hash_alg: ZoneMDHashAlg,

    /// The digest.
    ///
    /// This field stores the digest, as computed by the specified scheme and
    /// hash algorithm. While it is dictated by a generic parameter, it should
    /// almost always be `[u8]` or `[u8; N]` for some hard-coded size. This
    /// genericity can help construct it.
    ///
    /// The digest is required to be 12 bytes or more in size, but it is
    /// generally not advisable to truncate cryptographic hash functions.
    pub digest: Digest,
}

//--- Formatting

impl<Digest: ?Sized + AsRef<[u8]>> fmt::Debug for ZoneMD<Digest> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct DigestFmt<'a>(&'a [u8]);

        impl fmt::Debug for DigestFmt<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut first = true;
                for chunk in self.0.chunks(2) {
                    if !first {
                        f.write_str(" ")?;
                    }
                    first = false;
                    for &c in chunk {
                        write!(f, "{c:02x}")?;
                    }
                }
                Ok(())
            }
        }

        f.debug_struct("ZoneMD")
            .field("serial", &self.serial)
            .field("scheme", &self.scheme)
            .field("hash_alg", &self.hash_alg)
            .field("digest", &DigestFmt(self.digest.as_ref()))
            .finish()
    }
}

//--- Cloning

// The following impl would be ideal, but it conflicts with
// 'impl<T: Clone> Clone for Box<T>'.
//
//impl<Digest: UnsizedCopy> Clone for Box<ZoneMD<Digest>> { ... }
//
// The common case is 'ZoneMD<[u8]>' (i.e. just 'ZoneMD'), so we only
// implement 'Clone' for that.
#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<ZoneMD<[u8]>> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//--- Canonical operations

impl<Digest: ?Sized + BuildBytes + Ord> CanonicalRecordData
    for ZoneMD<Digest>
{
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        u32::from(self.serial)
            .cmp(&other.serial.into())
            .then(self.scheme.cmp(&other.scheme))
            .then(self.hash_alg.cmp(&other.hash_alg))
            .then_with(|| self.digest.cmp(&other.digest))
    }
}

//--- Parsing record data

impl<'a, Digest: ?Sized + ParseBytesZC> ParseRecordData<'a>
    for &'a ZoneMD<Digest>
{
}

impl<'a, Digest: ?Sized + ParseBytesZC> ParseRecordDataBytes<'a>
    for &'a ZoneMD<Digest>
{
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::ZONEMD => ZoneMD::parse_bytes_by_ref(bytes),
            _ => Err(ParseError),
        }
    }
}

//--- Building into DNS messages

impl<Digest: ?Sized + BuildBytes> BuildInMessage for ZoneMD<Digest> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = contents.get_mut(start..).ok_or(TruncationError)?;
        let rest_len = self.build_bytes(bytes)?.len();
        Ok(contents.len() - rest_len)
    }
}

//----------- ZoneMDScheme ---------------------------------------------------

/// A scheme for computing [`ZoneMD`] digests.
///
/// This enumeration describes the [`ZoneMD::scheme`] field. It is specified
/// by [RFC 8976, section 2.2.2]. IANA maintains [a registry][iana] of defined
/// schemes.
///
/// [RFC 8976, section 2.2.2]: https://www.rfc-editor.org/rfc/rfc8976.html#section-2.2.2
/// [iana]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#zonemd-schemes
///
/// Scheme values 240-254 (inclusive) are allocated for "Private Use". Scheme
/// values 0 and 255 are "Reserved".
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct ZoneMDScheme {
    /// The scheme code.
    pub code: u8,
}

//--- Associated Constants

impl ZoneMDScheme {
    /// The SIMPLE scheme.
    ///
    /// SIMPLE is, as expected, a simple scheme for computing the ZONEMD
    /// digest. It is specified by [RFC 8976, section 3.3.1]. At present,
    /// implementations are required to support it.
    ///
    /// [RFC 8976, section 3.3.1]: https://www.rfc-editor.org/rfc/rfc8976.html#section-3.3.1
    ///
    /// SIMPLE includes glue records and occluded data in the zone, sorts it
    /// in DNSSEC canonical order, and passes the entire zone (i.e. records
    /// serialized in the DNSSEC canonical wire format, concatenated together)
    /// into a single invocation of the hash function.
    pub const SIMPLE: Self = Self { code: 1 };
}

//--- Formatting

impl fmt::Debug for ZoneMDScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::SIMPLE => "ZoneMDScheme::SIMPLE",
            _ => return write!(f, "ZoneMDScheme({})", self.code),
        })
    }
}

//----------- ZoneMDHashAlg --------------------------------------------------

/// A hash algorithm for computing [`ZoneMD`] digests.
///
/// This enumeration describes the [`ZoneMD::hash_alg`] field. It is specified
/// by [RFC 8976, section 2.2.3]. IANA maintains [a registry][iana] of defined
/// hash algorithms.
///
/// [RFC 8976, section 2.2.3]: https://www.rfc-editor.org/rfc/rfc8976.html#section-2.2.3
/// [iana]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#zonemd-hash-algorithms
///
/// Algorithm values 240-254 (inclusive) are allocated for "Private Use".
/// Algorithm values 0 and 255 are "Reserved".
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct ZoneMDHashAlg {
    /// The algorithm code.
    pub code: u8,
}

//--- Associated Constants

impl ZoneMDHashAlg {
    /// The SHA384 algorithm.
    ///
    /// The resulting digest is 48 bytes in size, and must not be truncated.
    /// At present, implementations are required to support it.
    pub const SHA384: Self = Self { code: 1 };

    /// The SHA512 algorithm.
    ///
    /// The resulting digest is 64 bytes in size, and must not be truncated.
    /// At present, implementations are recommended to support it.
    pub const SHA512: Self = Self { code: 2 };
}

//--- Formatting

impl fmt::Debug for ZoneMDHashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::SHA384 => "ZoneMDHashAlg::SHA384",
            Self::SHA512 => "ZoneMDHashAlg::SHA512",
            _ => return write!(f, "ZoneMDHashAlg({})", self.code),
        })
    }
}
