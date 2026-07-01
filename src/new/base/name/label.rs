//! Labels in domain names.

use core::{
    borrow::{Borrow, BorrowMut},
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    iter::FusedIterator,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use crate::new::base::build::{BuildInMessage, NameCompressor};
use crate::new::base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new::base::wire::{
    AsBytes, BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError,
};
use crate::utils::dst::{UnsizedCopy, UnsizedCopyFrom};

//----------- Label ----------------------------------------------------------

/// A label in a domain name.
///
/// A domain name like `www.example.org.` contains 4 labels: `www`, `example`,
/// `org`, and the root label. They are encoded (in the DNS wire format) like
/// `3 www 7 example 3 org 0`, where each number is called a _length octet_.
/// In general, a label consists of 0 to 63 (inclusive) bytes of arbitrary
/// data, preceded by a 1-byte length octet.
///
/// A `Label` is simple wrapper around `[u8]`, and must be used in similar
/// ways (e.g. `&Label`, `Box<Label>`). It is a byte slice beginning with a
/// length octet, followed by the specified number of bytes. A `Label` for
/// `www` would contain the bytes `\x03www`.
///
/// `Label`s are rarely used directly; the vast majority of their uses occur
/// as part of domain names like [`Name`](super::Name).
///
/// ## Constructing a `Label`
///
/// `Label` is a _dynamically sized type_ (DST), like `[u8]`, which makes it a
/// little unwieldy. It is most easily used by reference, i.e. `&Label`.
///
/// You can parse a `Label` from the DNS wire format using
/// [`<&Label>::split_bytes()`] (when the input might contain data after the
/// label) or [`<&Label>::parse_bytes()`] (when the input ends right after
/// the label).
///
/// [`<&Label>::split_bytes()`]: #method.split_bytes
/// [`<&Label>::parse_bytes()`]: #method.parse_bytes
///
/// The [`label`] macro is helpful for writing tests, and it shows up in many
/// of the tests and examples here. It constructs a label from a hard-coded
/// (byte) string literal.
///
/// ```
/// # use domain::new::base::name::{Label, label};
/// # use domain::new::base::wire::{ParseError, ParseBytes, SplitBytes};
/// #
/// let input = b"\x03www\x07example\x03org\x00";
/// let (label, input) = <&Label>::split_bytes(input)?;
/// assert_eq!(label.contents(), b"www");
/// let (label, input) = <&Label>::split_bytes(input)?;
/// assert_eq!(label.contents(), b"example");
/// let (label, input) = <&Label>::split_bytes(input)?;
/// assert_eq!(label.contents(), b"org");
/// let (label, input) = <&Label>::split_bytes(input)?;
/// assert_eq!(label.contents(), b"");
///
/// let input = b"\x07example";
/// let label: &Label = <&Label>::parse_bytes(input)?;
/// assert_eq!(label.contents(), b"example");
/// assert_eq!(label.as_wire(), b"\x07example");
/// // `label` is not a copy of the input; it refers to the same address.
/// assert_eq!(label.as_wire().as_ptr(), input.as_ptr());
///
/// // You may see `label!` used in examples here.
/// // It generates a `&'static Label` for hard-coded labels.
/// assert_eq!(label, label!(b"example"));
/// #
/// # Ok::<(), ParseError>(())
/// ```
///
/// While `&Label` is the preferred way of handling labels, you may sometimes
/// need to store them 'on their own', without a lifetime. With a byte slice,
/// you could achieve this using `Box<[u8]>` or `Vec<u8>`. For `Label`, you
/// can use `Box<Label>` or [`LabelBuf`].
///
/// ```
/// # #![cfg(feature = "alloc")]
/// # use domain::new::base::name::{Label, LabelBuf, label};
/// # use domain::new::base::wire::ParseBytes;
/// # use domain::utils::dst::{UnsizedCopy, UnsizedCopyFrom};
/// #
/// let label: &Label = label!(b"example");
///
/// // Copy into a fixed-size buffer (ideal for modification):
/// let buffer: LabelBuf = label.to_buf();
/// let buffer: LabelBuf = label.unsized_copy_into();
/// let buffer: LabelBuf = LabelBuf::copy_from(label);
/// let buffer: LabelBuf = LabelBuf::unsized_copy_from(label);
///
/// // Copy into a heap allocation (ideal for long-term storage):
/// let boxed: Box<Label> = label.to_boxed();
/// let boxed: Box<Label> = label.unsized_copy_into();
/// let boxed: Box<Label> = Box::unsized_copy_from(label);
/// ```
///
/// ## Accessing the bytes
///
/// `Label` does not implement [`AsRef<[u8]>`] or provide other conveniences
/// to access the underlying bytes, because it is unclear whether the
/// implementation should include the length octet with those bytes.
///
/// [`AsRef<[u8]>`]: core::convert::AsRef
///
/// The preferred ways to access the bytes are [`Self::as_wire()`] (which
/// explicitly includes the length octet) and [`Self::contents()`] (which
/// explicitly does not).
///
/// `Label`'s implementation of [`AsBytes`] includes the length octet, as
/// [`AsBytes`] is primarily intended for encoding into a byte stream as in
/// the DNS wire format.
#[derive(AsBytes, UnsizedCopy)]
#[repr(transparent)]
pub struct Label([u8]);

//--- Associated Constants

impl Label {
    /// The root label.
    pub const ROOT: &'static Self = {
        // SAFETY: This is a correctly encoded label.
        unsafe { Self::from_bytes_unchecked(&[0]) }
    };

    /// The wildcard label.
    pub const WILDCARD: &'static Self = {
        // SAFETY: This is a correctly encoded label.
        unsafe { Self::from_bytes_unchecked(&[1, b'*']) }
    };

    /// Printable ASCII characters that can appear in labels printed in zone
    /// files without escaping.
    ///
    /// Rationale is described in [`Label#zone-file-formatting`].
    const UNESCAPED_ZONEFILE_CHARS: &[u8] = b"\
        ABCDEFGHIJKLMNOPQRSTUVWXYZ\
        abcdefghijklmnopqrstuvwxyz\
        0123456789\
        !#$%&'*+,-^_`{|}~";
}

//--- Construction

impl Label {
    /// Assume a byte slice is a valid label.
    ///
    /// This can be used to cast a label encoded in the wire format into the
    /// [`Label`] type without copying.
    ///
    /// For a checked, safe version, use [`<&Label>::parse_bytes()`].
    ///
    /// [`<&Label>::parse_bytes()`]: #method.parse_bytes
    ///
    /// ```
    /// # use domain::new::base::name::Label;
    /// #
    /// let encoded: &[u8] = b"\x07example";
    /// let label: &Label = unsafe { Label::from_bytes_unchecked(encoded) };
    /// ```
    ///
    /// # Safety
    ///
    /// The following conditions must hold for this call to be sound:
    /// - `bytes.len() <= 64`
    /// - `bytes[0] as usize + 1 == bytes.len()`
    #[must_use]
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Label' is 'repr(transparent)' to '[u8]'.
        unsafe { core::mem::transmute(bytes) }
    }

    /// Assume a mutable byte slice is a valid label.
    ///
    /// This can be used to cast a label encoded in the wire format into the
    /// [`Label`] type without copying, while retaining mutable access.
    ///
    /// ```
    /// # use domain::new::base::name::Label;
    /// #
    /// let mut encoded: [u8; 8] = *b"\x07example";
    /// let label: &mut Label = unsafe {
    ///     Label::from_mut_bytes_unchecked(&mut encoded)
    /// };
    /// ```
    ///
    /// # Safety
    ///
    /// The following conditions must hold for this call to be sound:
    /// - `bytes.len() <= 64`
    /// - `bytes[0] as usize + 1 == bytes.len()`
    #[must_use]
    pub const unsafe fn from_mut_bytes_unchecked(
        bytes: &mut [u8],
    ) -> &mut Self {
        // SAFETY: 'Label' is 'repr(transparent)' to '[u8]'.
        unsafe { core::mem::transmute(bytes) }
    }
}

//--- Manipulation

impl Label {
    /// Copy the label into a [`LabelBuf`].
    ///
    /// This is equivalent to [`LabelBuf::copy_from()`], but may be more
    /// convenient to use in some cases.
    ///
    /// This is a concrete, inherent, and `const` version of
    /// [`Self::unsized_copy_into()`].
    #[must_use]
    pub const fn to_buf(&self) -> LabelBuf {
        LabelBuf::copy_from(self)
    }

    /// Copy the label into a [`Box<Label>`].
    ///
    /// [`Box<Label>`]: alloc::boxed::Box
    ///
    /// This is a concrete, inherent version of [`Self::unsized_copy_into()`].
    #[must_use]
    #[cfg(feature = "alloc")]
    pub fn to_boxed(&self) -> alloc::boxed::Box<Label> {
        self.unsized_copy_into()
    }

    /// Lowercase the label.
    ///
    /// All ASCII uppercase characters in the label will be lowercased.
    ///
    /// ```
    /// # use domain::new::base::name::label_buf;
    /// #
    /// let mut buffer = label_buf!(b"eXAMpLE");
    /// buffer.make_lowercase();
    /// assert_eq!(buffer.contents(), b"example");
    /// ```
    pub const fn make_lowercase(&mut self) {
        // We include the length octet. It is strictly less than 64, so is
        // never a valid ASCII alphabetic character, and so it will not be
        // affected.
        self.0.make_ascii_lowercase()
    }
}

//--- Parsing from DNS messages

impl<'a> ParseMessageBytes<'a> for &'a Label {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(&contents[start..])
    }
}

impl<'a> SplitMessageBytes<'a> for &'a Label {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        Self::split_bytes(&contents[start..])
            .map(|(this, rest)| (this, contents.len() - start - rest.len()))
    }
}

//--- Building into DNS messages

impl BuildInMessage for Label {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = self.as_wire();
        let end = start + bytes.len();
        contents
            .get_mut(start..end)
            .ok_or(TruncationError)?
            .copy_from_slice(bytes);
        Ok(end)
    }
}

//--- Parsing from bytes

impl<'a> SplitBytes<'a> for &'a Label {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let &size = bytes.first().ok_or(ParseError)?;
        if size < 64 && bytes.len() > size as usize {
            let (label, rest) = bytes.split_at(1 + size as usize);
            // SAFETY:
            // - 'label.len() = 1 + size <= 64'
            // - 'label[0] = size + 1 == label.len()'
            Ok((unsafe { Label::from_bytes_unchecked(label) }, rest))
        } else {
            Err(ParseError)
        }
    }
}

impl<'a> ParseBytes<'a> for &'a Label {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        match Self::split_bytes(bytes) {
            Ok((this, &[])) => Ok(this),
            _ => Err(ParseError),
        }
    }
}

//--- Building into byte sequences

/// Serializing a [`Label`] as bytes.
///
/// Labels are serialized exactly as [`Label::as_wire()`], their encoding in
/// the DNS wire format: a one-byte length octet (between 0 and 63, inclusive)
/// followed by that many bytes.
impl BuildBytes for Label {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_wire().build_bytes(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        self.as_wire().len()
    }
}

//--- Inspection

impl Label {
    /// Whether this is the root label.
    ///
    /// Equivalent to `self == Label::ROOT`.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        // We don't need to look at the length octet directly; it is always
        // equal to `self.0.len() - 1`.
        self.0.len() == 1
    }

    /// Whether this is a wildcard label.
    ///
    /// Equivalent to `self == Label::WILDCARD`.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self.0, [1, b'*'])
    }

    /// The encoding of the label in the DNS wire format.
    ///
    /// This includes the length octet. It is also accessible via
    /// [`Self::as_bytes()`] and [`Self::build_bytes()`]. If you don't need
    /// the length octet, use [`Self::contents()`].
    ///
    /// ```
    /// # use domain::new::base::name::label;
    /// #
    /// let label = label!(b"example");
    /// assert_eq!(label.as_wire(), b"\x07example");
    /// assert_eq!(label.contents(), b"example");
    /// ```
    #[must_use]
    pub const fn as_wire(&self) -> &[u8] {
        &self.0
    }

    /// The contents of the label.
    ///
    /// This does not include the length octet. If you need the length octet,
    /// use [`Self::as_wire()`]. Use [`Self::contents_mut()`] for a mutable
    /// view.
    ///
    /// ```
    /// # use domain::new::base::name::label;
    /// #
    /// let label = label!(b"example");
    /// assert_eq!(label.contents(), b"example");
    /// assert_eq!(label.as_wire(), b"\x07example");
    /// ```
    #[must_use]
    pub const fn contents(&self) -> &[u8] {
        // TODO: direct slicing is not possible in `const` yet.
        //   See <https://github.com/rust-lang/rust/issues/143775>.
        // SAFETY: A `Label` always has a length octet.
        unsafe { self.0.split_at_unchecked(1).1 }
    }

    /// The contents of the label, mutably.
    ///
    /// This does not include the length octet. There is no method to get a
    /// mutable byte slice from [`Label`] including the length octet, because
    /// modifying it would result in an invalid label.
    ///
    /// ```
    /// # use domain::new::base::name::{Label, label_buf};
    /// # use domain::new::base::wire::ParseBytes;
    /// #
    /// let mut buffer = label_buf!(b"example");
    /// let label: &mut Label = buffer.as_mut_label();
    /// assert_eq!(label.contents_mut(), b"example");
    /// ```
    #[must_use]
    pub const fn contents_mut(&mut self) -> &mut [u8] {
        // NOTE: `Label`'s only safety invariant is that the length octet is
        // well-formed (it is consistent with the slice length and is less
        // than 64). No matter what the caller does with the returned bytes,
        // they cannot violate that invariant.
        //
        // TODO: slicing is not possible in `const` yet.
        // SAFETY: A `Label` always has a length octet.
        unsafe { self.0.split_at_mut_unchecked(1).1 }
    }
}

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<Label> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//--- Comparison

impl PartialEq for Label {
    /// Compare two labels for equality.
    ///
    /// Labels are compared ASCII-case-insensitively, as is conventional for
    /// DNS. For a case-sensitive comparison, you can compare the byte slices
    /// (from [`Self::contents()`], not [`Self::as_wire()`]!) manually.
    ///
    /// ```
    /// # use domain::new::base::name::label;
    /// #
    /// let a = label!(b"example");
    /// let b = label!(b"eXAMpLE");
    /// let c = label!(b"unrelated");
    /// assert_eq!(a, b);
    /// assert_ne!(a.contents(), b.contents());
    /// assert_ne!(a, c);
    /// ```
    fn eq(&self, other: &Self) -> bool {
        // The length octet is strictly less than 64, so it cannot be an ASCII
        // alphabetic character. This means that it is safe to include in an
        // ASCII-case-insensitive comparison.
        //
        // We don't need to include it, because the lengths of the slices will
        // be checked already. But it is probably more efficient this way.
        // Maybe we'll benchmark it one day and find out.
        self.as_wire().eq_ignore_ascii_case(other.as_wire())
    }
}

impl Eq for Label {}

//--- Ordering

impl PartialOrd for Label {
    /// Determine the order between two labels.
    ///
    /// See [`Label::cmp()`].
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Label {
    /// Determine the order between two labels.
    ///
    /// Labels are compared ASCII-case-insensitively by their contents, as is
    /// conventional for DNS. Labels are equal if their corresponding bytes
    /// are equal (ignoring ASCII case). If their corresponding bytes are not
    /// equal, the ordering is determined by the first mismatched byte. If one
    /// label is a prefix of the other (i.e. all their corresponding bytes are
    /// equal, but one has fewer bytes), it is considered less than the other.
    ///
    /// For a case-sensitive comparison, you can compare the byte slices (from
    /// [`Self::contents()`], not [`Self::as_wire()`]!) manually.
    ///
    /// ```
    /// # use domain::new::base::name::label;
    /// #
    /// let a = label!(b"example");
    /// let b = label!(b"example-");
    /// let c = label!(b"org");
    /// assert!(a < b);
    /// assert!(a < c);
    /// assert!(b < c);
    /// ```
    fn cmp(&self, other: &Self) -> Ordering {
        // NOTE: The standard library provides `eq_ignore_ascii_case()`, but
        // not `cmp_ignore_ascii_case()`. So we implement it manually.
        let this = self.contents().iter().map(u8::to_ascii_lowercase);
        let that = other.contents().iter().map(u8::to_ascii_lowercase);
        this.cmp(that)
    }
}

//--- Hashing

impl Hash for Label {
    /// Hash this label.
    ///
    /// All uppercase ASCII characters are lowercased before being hashed.
    /// Thus, the hash is case-independent, consistent with how labels are
    /// compared and ordered. The length octet is also hashed.
    ///
    /// ```
    /// # use std::collections::hash_map::RandomState;
    /// # use std::hash::BuildHasher;
    /// # use domain::new::base::name::label;
    /// #
    /// # let hasher = RandomState::default();
    /// let a = label!(b"example");
    /// let b = label!(b"eXAMpLE");
    /// assert_eq!(a, b);
    /// assert_ne!(a.contents(), b.contents());
    /// assert_eq!(hasher.hash_one(a), hasher.hash_one(b));
    /// ```
    fn hash<H: Hasher>(&self, state: &mut H) {
        // NOTE: The length octet is unaffected by `to_ascii_lowercase()`
        // because it is strictly less than 64.
        for &byte in self.as_wire() {
            state.write_u8(byte.to_ascii_lowercase())
        }
    }
}

//--- Formatting

impl fmt::Display for Label {
    /// Print a label.
    ///
    /// There is no one convention for formatting DNS labels. Labels are
    /// usually formatted as part of a domain name, and it is not entirely
    /// clear how they should be formatted on their own. See the examples
    /// here to understand how this implementation works.
    ///
    /// To parse a label _from_ this format, see [`LabelBuf::from_str()`].
    /// [`Label`] cannot implement [`FromStr`] itself.
    ///
    /// The root label is printed as an empty string. Labels are usually
    /// delimited by `.`s when printing domain names, so this should be
    /// consistent with formatting domain names like `example.org.`.
    ///
    /// Certain characters are escaped using backslashes. There are two
    /// escape formats: `\\X`, where `X` is the character being escaped
    /// (used when `X` is a printable ASCII character), and `\\DDD`, where
    /// `DDD` is the byte value in decimal, zero-padded to three characters.
    ///
    /// The following printable ASCII characters are escaped by this version
    /// of the implementation:
    ///
    /// - `"` (`0x22`), `(` (`0x28`), `)` (`0x29`), `@` (`0x40`), `\\`
    ///   (`0x5C`): these characters are interpreted specially in zone files.
    ///
    /// - `/` (`0x2F`), `:` (`0x3A`), `;` (`0x3B`), `<` (`0x3C`), `=`
    ///   (`0x3D`), `>` (`0x3E`), `?` (`0x3F`) `[` (`0x5B`), `]` (`0x5D`):
    ///   these characters are sometimes used to delimit URLs, which may be
    ///   nothing more than domain names.
    ///
    /// The following printable ASCII characters are _not_ escaped by this
    /// version of the implementation: `!`, `#`, `$`, `%`, `&`, `'`, `*`, `+`,
    /// `,`, `-`, `^`, `_`, `\``, `~`, `{`, `|`, `}`.
    ///
    /// Note that ASCII space ` ` is not considered a printable character; it
    /// will be printed as `\\032`.
    ///
    /// Because the zone file format (which is the primary motivation for
    /// this implementation) is quite under-specified, the details of this
    /// implementation may change over time. Some printable ASCII characters
    /// that are not escaped today may be escaped in the future. Characters
    /// that are escaped using `\\X` syntax today could be escaped using
    /// `\\DDD` syntax in the future.
    ///
    /// ```
    /// # use domain::new::base::name::{Label, label};
    /// #
    /// // The simple case is pretty simple.
    /// assert_eq!(label!(b"example").to_string(), "example");
    ///
    /// // Uppercase characters are printed as such.
    /// assert_eq!(label!(b"eXAMplE").to_string(), "eXAMplE");
    ///
    /// // The root label is an empty string.
    /// assert_eq!(Label::ROOT.to_string(), "");
    ///
    /// // Non-ASCII characters are escaped.
    /// let label = label!(b"helloworld\xF0\x9F\x8F\xB3\xEF\xB8\x8F\xE2\x80\x8D\xE2\x9A\xA7\xEF\xB8\x8F");
    /// assert_eq!(label.to_string(),
    ///     r"helloworld\240\159\143\179\239\184\143\226\128\141\226\154\167\239\184\143");
    ///
    /// // Uncommon and non-printable ASCII characters are escaped too.
    /// let label = label!(b"\x00\x0A!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\x7F");
    /// assert_eq!(label.to_string(),
    ///     r##"\000\010!\"#$%&'\(\)*+,-\.\/\:\;\<\=\>\?\@\[\\\]^_`{|}~\127"##);
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.contents().iter().try_for_each(|&byte| {
            if Label::UNESCAPED_ZONEFILE_CHARS.contains(&byte) {
                write!(f, "{}", byte as char)
            } else if byte.is_ascii_graphic() {
                write!(f, "\\{}", byte as char)
            } else {
                write!(f, "\\{:03}", byte)
            }
        })
    }
}

impl fmt::Debug for Label {
    /// Print a label for debugging purposes.
    ///
    /// The format used might change in the future, and is not documented to
    /// prevent it from being relied upon.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label(\"{self}\")")
    }
}

//--- Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for Label {
    /// Serialize a label.
    ///
    /// See [the Serde data model](https://serde.rs/data-model.html) for an
    /// understanding of the terms here.
    ///
    /// Labels are serialized as `newtype_struct`s of name `Label`. For
    /// human-readable formats (e.g. JSON and TOML), they are serialized
    /// as per [`<Label as Display>::fmt()`]. For compact formats (e.g.
    /// Postcard), they are serialized as byte slices (specifically
    /// [`Self::contents()`], excluding the length octet).
    ///
    /// [`<Label as Display>::fmt()`]: #method.fmt
    ///
    /// To deserialize a label, see [`LabelBuf::deserialize()`] or
    /// [`<Box<Label>>::deserialize()`]. They use exactly the same format.
    /// [`Label`] cannot implement [`serde::Deserialize`] itself.
    ///
    /// [`LabelBuf::deserialize()`]: struct.LabelBuf.html#method.deserialize
    /// [`<Box<Label>>::deserialize()`]: #method.deserialize
    ///
    /// ```
    /// # use serde_test::{Configure, Token, assert_ser_tokens};
    /// # use domain::new::base::name::label;
    /// #
    /// assert_ser_tokens(&label!(b"example\x7Fabc").readable(), &[
    ///     Token::NewtypeStruct { name: "Label" },
    ///     Token::String("example\\127abc"),
    /// ]);
    /// assert_ser_tokens(&label!(b"example\x7Fabc").compact(), &[
    ///     Token::NewtypeStruct { name: "Label" },
    ///     Token::Bytes(b"example\x7Fabc"),
    /// ]);
    /// ```
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer
                .serialize_newtype_struct("Label", &format_args!("{self}"))
        } else {
            // `impl Serialize for [u8]` serializes to `Seq`, not `Bytes`.

            struct NV<'a>(&'a [u8]);

            impl serde::Serialize for NV<'_> {
                fn serialize<S>(
                    &self,
                    serializer: S,
                ) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    serializer.serialize_bytes(self.0)
                }
            }

            serializer.serialize_newtype_struct("Label", &NV(self.contents()))
        }
    }
}

//----------- LabelBuf -------------------------------------------------------

/// A 64-byte buffer holding a [`Label`].
#[derive(Clone)]
#[repr(transparent)]
pub struct LabelBuf {
    /// The label bytes.
    data: [u8; 64],
}

//--- Construction

impl LabelBuf {
    /// Construct a new, empty [`LabelBuf`].
    ///
    /// The resulting buffer contains the root label. It can be appended to.
    #[must_use]
    pub const fn new() -> Self {
        Self { data: [0u8; 64] }
    }

    /// Copy a [`Label`] into a buffer.
    ///
    /// This is a concrete, inherent, and `const` version of
    /// [`Self::unsized_copy_from()`].
    ///
    /// ```
    /// # use domain::new::base::name::{LabelBuf, label};
    /// # use domain::new::base::wire::ParseBytes;
    /// #
    /// let buffer: LabelBuf = LabelBuf::copy_from(label!(b"example"));
    /// assert_eq!(buffer.as_wire(), b"\x07example");
    /// ```
    #[must_use]
    pub const fn copy_from(label: &Label) -> Self {
        let bytes = label.as_wire();
        let mut data = [0u8; 64];
        // TODO: `for` loops and slicing aren't `const` yet.
        let mut index = 0usize;
        while index < bytes.len() {
            data[index] = bytes[index];
            index += 1;
        }
        Self { data }
    }
}

impl Default for LabelBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl UnsizedCopyFrom for LabelBuf {
    type Source = Label;

    fn unsized_copy_from(value: &Self::Source) -> Self {
        Self::copy_from(value)
    }
}

//--- Manipulation

impl LabelBuf {
    /// Append bytes to the label.
    ///
    /// The length octet will be adjusted automatically.
    ///
    /// ```
    /// # use domain::new::base::name::LabelBuf;
    /// #
    /// let mut buffer = LabelBuf::new();
    /// buffer.append(b"hello").unwrap();
    /// buffer.append(b"world").unwrap();
    /// assert_eq!(buffer.as_wire(), b"\x0Ahelloworld");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TruncationError`] if the bytes do not fit in the buffer.
    /// The buffer will be unmodified.
    pub const fn append(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), TruncationError> {
        let len = self.data[0] as usize;
        // PANIC: `len < 64`, and `bytes.len() <= isize::MAX` as that is the
        // largest legal size of an allocation. So this addition will not
        // overflow.
        let new_len = len + bytes.len();
        if new_len >= 64 {
            return Err(TruncationError);
        }

        // TODO: direct slicing is not possible in `const` yet.
        //   See <https://github.com/rust-lang/rust/issues/143775>.
        // SAFETY:
        // - `1 + len <= 64 = data.len()`.
        // - `new_len = len + bytes.len() < 64`.
        // - Thus `bytes.len() < 64 - len`.
        // - Thus `bytes.len() <= 64 - (1 + len)`.
        let target = unsafe {
            self.data
                .split_at_mut_unchecked(1 + len)
                .1
                .split_at_mut_unchecked(bytes.len())
                .0
        };
        target.copy_from_slice(bytes);
        self.data[0] = new_len as u8;

        Ok(())
    }

    /// Append a single byte to the label.
    ///
    /// The length octet will be adjusted automatically.
    ///
    /// Also see [`Self::append()`].
    ///
    /// ```
    /// # use domain::new::base::name::LabelBuf;
    /// #
    /// let mut buffer = LabelBuf::new();
    /// buffer.append(b"hello").unwrap();
    /// buffer.push(b'4').unwrap();
    /// buffer.push(b'2').unwrap();
    /// assert_eq!(buffer.as_wire(), b"\x07hello42");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TruncationError`] if the byte does not fit in the buffer.
    /// The buffer will be unmodified.
    pub const fn push(&mut self, byte: u8) -> Result<(), TruncationError> {
        let len = self.data[0] as usize;
        if len >= 63 {
            return Err(TruncationError);
        }

        self.data[1 + len] = byte;
        self.data[0] = 1 + len as u8;
        Ok(())
    }

    /// Truncate the label to a particular length.
    ///
    /// The length octet will be adjusted automatically.
    ///
    /// ```
    /// # use domain::new::base::name::LabelBuf;
    /// #
    /// let mut buffer = LabelBuf::new();
    /// buffer.append(b"example");
    /// assert_eq!(buffer.as_wire(), b"\x07example");
    /// buffer.truncate(4);
    /// assert_eq!(buffer.as_wire(), b"\x04exam");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the label is strictly shorter than `new_len`.
    pub const fn truncate(&mut self, new_len: usize) {
        // TODO: Include `len` and `new_len` in the assert message once it is
        // `const`-safe to do so.
        let len = self.data[0] as usize;
        assert!(new_len <= len, "Label is shorter than desired length");
        self.data[0] = new_len as u8;
    }
}

//--- Parsing from DNS messages

impl ParseMessageBytes<'_> for LabelBuf {
    fn parse_message_bytes(
        contents: &'_ [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(&contents[start..])
    }
}

impl SplitMessageBytes<'_> for LabelBuf {
    fn split_message_bytes(
        contents: &'_ [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        Self::split_bytes(&contents[start..])
            .map(|(this, rest)| (this, contents.len() - start - rest.len()))
    }
}

//--- Building into DNS messages

impl BuildInMessage for LabelBuf {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        Label::build_in_message(self, contents, start, compressor)
    }
}

//--- Parsing from byte sequences

impl ParseBytes<'_> for LabelBuf {
    fn parse_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        <&Label>::parse_bytes(bytes).map(Self::copy_from)
    }
}

impl SplitBytes<'_> for LabelBuf {
    fn split_bytes(bytes: &'_ [u8]) -> Result<(Self, &'_ [u8]), ParseError> {
        <&Label>::split_bytes(bytes)
            .map(|(label, rest)| (Self::copy_from(label), rest))
    }
}

//--- Building into byte sequences

impl BuildBytes for LabelBuf {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        (**self).build_bytes(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        (**self).built_bytes_size()
    }
}

//--- Access to the underlying 'Label'

impl LabelBuf {
    /// Access the underlying [`Label`].
    ///
    /// This is a `const` version of [`Self::deref()`].
    #[must_use]
    pub const fn as_label(&self) -> &Label {
        let size = self.data[0];
        // TODO: slicing is not possible in `const` yet.
        // SAFETY: `size < 64`.
        let label = unsafe {
            core::slice::from_raw_parts(self.data.as_ptr(), 1 + size as usize)
        };
        // SAFETY: A `LabelBuf` always contains a valid `Label`.
        unsafe { Label::from_bytes_unchecked(label) }
    }

    /// Access the underlying [`Label`] mutably.
    ///
    /// This is a `const` version of [`Self::deref_mut()`].
    #[must_use]
    pub const fn as_mut_label(&mut self) -> &mut Label {
        let size = self.data[0];
        // TODO: slicing is not possible in `const` yet.
        // SAFETY: `size < 64`.
        let label = unsafe {
            core::slice::from_raw_parts_mut(
                self.data.as_mut_ptr(),
                1 + size as usize,
            )
        };
        // SAFETY: A `LabelBuf` always contains a valid `Label`.
        unsafe { Label::from_mut_bytes_unchecked(label) }
    }
}

impl Deref for LabelBuf {
    type Target = Label;

    fn deref(&self) -> &Self::Target {
        self.as_label()
    }
}

impl DerefMut for LabelBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_label()
    }
}

impl Borrow<Label> for LabelBuf {
    fn borrow(&self) -> &Label {
        self
    }
}

impl BorrowMut<Label> for LabelBuf {
    fn borrow_mut(&mut self) -> &mut Label {
        self
    }
}

impl AsRef<Label> for LabelBuf {
    fn as_ref(&self) -> &Label {
        self
    }
}

impl AsMut<Label> for LabelBuf {
    fn as_mut(&mut self) -> &mut Label {
        self
    }
}

//--- Forwarding equality, comparison, and hashing

impl PartialEq for LabelBuf {
    /// See [`Label::eq()`].
    fn eq(&self, that: &Self) -> bool {
        **self == **that
    }
}

impl Eq for LabelBuf {}

impl PartialOrd for LabelBuf {
    /// See [`Label::partial_cmp()`].
    fn partial_cmp(&self, that: &Self) -> Option<Ordering> {
        Some(self.cmp(that))
    }
}

impl Ord for LabelBuf {
    /// See [`Label::cmp()`].
    fn cmp(&self, that: &Self) -> Ordering {
        (**self).cmp(&**that)
    }
}

impl Hash for LabelBuf {
    /// See [`Label::hash()`].
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

//--- Forwarding formatting

impl fmt::Display for LabelBuf {
    /// See [`<Label as Display>::fmt()`].
    ///
    /// [`<Label as Display>::fmt()`]: struct.Label.html#method.fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl fmt::Debug for LabelBuf {
    /// Print a label for debugging purposes.
    ///
    /// The format used might change in the future, and is not documented to
    /// prevent it from being relied upon.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LabelBuf(\"{self}\")")
    }
}

//--- Parsing from strings

impl LabelBuf {
    /// Parse a printed label.
    ///
    /// This will parse a label from the format used by [`<Label as
    /// Display>::fmt()`]. Labels are usually parsed as part of a domain name,
    /// and it is not entirely clear how they should be parsed on their own.
    /// See the examples here to understand how this implementation works.
    ///
    /// [`<Label as Display>::fmt()`]: struct.Label.html#method.fmt
    ///
    /// This function is a direct inverse of [`<Label as Display>::fmt()`],
    /// but it cannot be used to parse a label embedded within a larger
    /// string. For that, see [`LabelBuf::split_str()`].
    ///
    /// ```
    /// # use domain::new::base::name::{LabelBuf, LabelParseError, label_buf};
    /// #
    /// assert_eq!(
    ///     LabelBuf::parse_str(b"example"),
    ///     Ok(label_buf!(b"example")));
    ///
    /// assert_eq!(
    ///     LabelBuf::parse_str(b"foo\\.b\\010r"),
    ///     Ok(label_buf!(b"foo.b\x0Ar")));
    ///
    /// // An empty input is parsed as the root label.
    /// assert_eq!(
    ///     LabelBuf::parse_str(b""),
    ///     Ok(LabelBuf::new()));
    ///
    /// // Irregular characters cause failure.
    /// assert_eq!(
    ///     LabelBuf::parse_str(b"example.com."),
    ///     Err(LabelParseError::InvalidChar));
    /// ```
    pub fn parse_str(mut s: &[u8]) -> Result<Self, LabelParseError> {
        // The buffer we'll fill into.
        let mut this = Self::new();

        // Parse character by character.
        loop {
            let &[b, ref rest @ ..] = s else {
                // The entire input has been consumed.
                return Ok(this);
            };
            s = rest;
            if Label::UNESCAPED_ZONEFILE_CHARS.contains(&b) {
                // A regular label character.
                this.push(b).map_err(|_| LabelParseError::Overlong)?;
            } else if b == b'\\' {
                // An escape character.
                let &[b, ref rest @ ..] = s else {
                    return Err(LabelParseError::PartialEscape);
                };
                let value = if b.is_ascii_digit() {
                    let (digits, rest) = s
                        .split_at_checked(3)
                        .ok_or(LabelParseError::PartialEscape)?;
                    s = rest;
                    let digits = core::str::from_utf8(digits)
                        .map_err(|_| LabelParseError::InvalidEscape)?;
                    digits
                        .parse()
                        .map_err(|_| LabelParseError::InvalidEscape)?
                } else if b.is_ascii_graphic() {
                    s = rest;
                    b
                } else {
                    return Err(LabelParseError::InvalidEscape);
                };
                this.push(value).map_err(|_| LabelParseError::Overlong)?;
            } else {
                return Err(LabelParseError::InvalidChar);
            };
        }
    }

    /// Parse a printed label from a larger string.
    ///
    /// This will parse a label from the format used by [`<Label as
    /// Display>::fmt()`]. Labels are usually parsed as part of a domain name,
    /// and it is not entirely clear how they should be parsed on their own.
    /// See the examples here to understand how this implementation works.
    ///
    /// [`<Label as Display>::fmt()`]: struct.Label.html#method.fmt
    ///
    /// This function is designed for use when parsing labels embedded within
    /// some larger string (e.g. a zone file). The string may be buffered,
    /// so only a part of it is provided; the string is considered to be
    /// infinitely long. A label is only parsed successfully once a delimiting
    /// byte (one that lies _after_ it) is found. As such, this function is
    /// **not** a perfect inverse of [`<Label as Display>::fmt()`]. For such
    /// an inverse, see [`LabelBuf::parse_str()`].
    ///
    /// ```
    /// # use domain::new::base::name::{LabelBuf, LabelSplitError, label_buf};
    /// #
    /// assert_eq!(
    ///     LabelBuf::split_str(b"example.com."),
    ///     Ok((label_buf!(b"example"), &b".com."[..])));
    ///
    /// assert_eq!(
    ///     LabelBuf::split_str(b"foo\\.b\\010r.com."),
    ///     Ok((label_buf!(b"foo.b\x0Ar"), &b".com."[..])));
    ///
    /// // Even though this looks like a valid label, there is no delimiting
    /// // byte, so it cannot be parsed successfully.
    /// assert_eq!(
    ///     LabelBuf::split_str(b"example"),
    ///     Err(LabelSplitError::ShortInput));
    ///
    /// // Any "uncommon" ASCII character, non-printable ASCII character, or
    /// // non-ASCII character can serve as the delimiting byte.
    /// assert_eq!(
    ///     LabelBuf::split_str(b"com:22"),
    ///     Ok((label_buf!(b"com"), &b":22"[..])));
    /// ```
    pub fn split_str(mut s: &[u8]) -> Result<(Self, &[u8]), LabelSplitError> {
        // The buffer we'll fill into.
        let mut this = Self::new();

        // Parse character by character.
        loop {
            let full = s;
            let &[b, ref rest @ ..] = s else {
                return Err(LabelSplitError::ShortInput);
            };
            s = rest;
            if Label::UNESCAPED_ZONEFILE_CHARS.contains(&b) {
                // A regular label character.
                this.push(b).map_err(|_| LabelSplitError::Overlong)?;
            } else if b == b'\\' {
                // An escape character.
                let &[b, ref rest @ ..] = s else {
                    return Err(LabelSplitError::ShortInput);
                };
                let value = if b.is_ascii_digit() {
                    let (digits, rest) = s
                        .split_at_checked(3)
                        .ok_or(LabelSplitError::ShortInput)?;
                    s = rest;
                    let digits = core::str::from_utf8(digits)
                        .map_err(|_| LabelSplitError::InvalidEscape)?;
                    digits
                        .parse()
                        .map_err(|_| LabelSplitError::InvalidEscape)?
                } else if b.is_ascii_graphic() {
                    s = rest;
                    b
                } else {
                    return Err(LabelSplitError::InvalidEscape);
                };
                this.push(value).map_err(|_| LabelSplitError::Overlong)?;
            } else {
                // An invalid character has been reached; the label has ended.
                break Ok((this, full));
            };
        }
    }
}

impl FromStr for LabelBuf {
    type Err = LabelParseError;

    /// Parse a printed label.
    ///
    /// See [`LabelBuf::parse_str()`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s.as_bytes())
    }
}

//--- Serialize, Deserialize

#[cfg(feature = "serde")]
impl serde::Serialize for LabelBuf {
    /// See [`Label::serialize()`].
    ///
    /// [`Label::serialize()`]: struct.Label.html#method.serialize
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'a> serde::Deserialize<'a> for LabelBuf {
    /// Deserialize a label.
    ///
    /// See [`Label::serialize()`] for a discussion of the format.
    ///
    /// [`Label::serialize()`]: struct.Label.html#method.serialize
    ///
    /// ```
    /// # use serde_test::{Configure, Token, assert_tokens};
    /// # use domain::new::base::name::label_buf;
    /// #
    /// assert_tokens(&label_buf!(b"example\x7Fabc").readable(), &[
    ///     Token::NewtypeStruct { name: "Label" },
    ///     Token::String("example\\127abc"),
    /// ]);
    /// assert_tokens(&label_buf!(b"example\x7Fabc").compact(), &[
    ///     Token::NewtypeStruct { name: "Label" },
    ///     Token::Bytes(b"example\x7Fabc"),
    /// ]);
    /// ```
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        if deserializer.is_human_readable() {
            struct V;

            impl serde::de::Visitor<'_> for V {
                type Value = LabelBuf;

                fn expecting(
                    &self,
                    f: &mut fmt::Formatter<'_>,
                ) -> fmt::Result {
                    f.write_str("a label, in the DNS zonefile format")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    v.parse().map_err(|err| E::custom(err))
                }
            }

            struct NV;

            impl<'a> serde::de::Visitor<'a> for NV {
                type Value = LabelBuf;

                fn expecting(
                    &self,
                    f: &mut fmt::Formatter<'_>,
                ) -> fmt::Result {
                    f.write_str("a DNS label")
                }

                fn visit_newtype_struct<D>(
                    self,
                    deserializer: D,
                ) -> Result<Self::Value, D::Error>
                where
                    D: serde::Deserializer<'a>,
                {
                    deserializer.deserialize_str(V)
                }
            }

            deserializer.deserialize_newtype_struct("Label", NV)
        } else {
            struct V;

            impl serde::de::Visitor<'_> for V {
                type Value = LabelBuf;

                fn expecting(
                    &self,
                    f: &mut fmt::Formatter<'_>,
                ) -> fmt::Result {
                    f.write_str("the contents of a DNS label")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let mut buf = LabelBuf::new();
                    buf.append(v).map_err(|_| {
                        E::custom(
                            "misformatted label for the DNS wire format",
                        )
                    })?;
                    Ok(buf)
                }
            }

            struct NV;

            impl<'a> serde::de::Visitor<'a> for NV {
                type Value = LabelBuf;

                fn expecting(
                    &self,
                    f: &mut fmt::Formatter<'_>,
                ) -> fmt::Result {
                    f.write_str("a DNS label")
                }

                fn visit_newtype_struct<D>(
                    self,
                    deserializer: D,
                ) -> Result<Self::Value, D::Error>
                where
                    D: serde::Deserializer<'a>,
                {
                    deserializer.deserialize_bytes(V)
                }
            }

            deserializer.deserialize_newtype_struct("Label", NV)
        }
    }
}

#[cfg(all(feature = "serde", feature = "alloc"))]
impl<'a> serde::Deserialize<'a> for alloc::boxed::Box<Label> {
    /// Deserialize a label and allocate it on the heap.
    ///
    /// See [`LabelBuf::deserialize()`].
    ///
    /// [`LabelBuf::deserialize()`]: struct.LabelBuf.html#method.deserialize
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        LabelBuf::deserialize(deserializer)
            .map(|this| this.unsized_copy_into())
    }
}

//----------- LabelIter ------------------------------------------------------

/// An iterator over encoded [`Label`]s.
#[derive(Clone)]
pub struct LabelIter<'a> {
    /// The buffer being read from.
    ///
    /// It is assumed to contain valid encoded labels.
    bytes: &'a [u8],
}

//--- Construction

impl<'a> LabelIter<'a> {
    /// Construct a new [`LabelIter`].
    ///
    /// # Safety
    ///
    /// The byte sequence must contain a sequence of valid encoded labels.
    pub const unsafe fn new_unchecked(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

//--- Inspection

impl<'a> LabelIter<'a> {
    /// The remaining labels.
    pub const fn remaining(&self) -> &'a [u8] {
        self.bytes
    }

    /// Whether the iterator is empty.
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

//--- Iteration

impl<'a> Iterator for LabelIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }

        // SAFETY: 'bytes' is assumed to only contain valid labels.
        let (head, tail) =
            unsafe { <&Label>::split_bytes(self.bytes).unwrap_unchecked() };
        self.bytes = tail;
        Some(head)
    }
}

impl FusedIterator for LabelIter<'_> {}

//--- Formatting

impl fmt::Debug for LabelIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Labels<'a>(&'a LabelIter<'a>);

        impl fmt::Debug for Labels<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.clone()).finish()
            }
        }

        f.debug_tuple("LabelIter").field(&Labels(self)).finish()
    }
}

//============ Macros ========================================================

/// Construct a hard-coded [`Label`] at compile time.
///
/// This is a convenience function for writing example-based tests; it
/// provides a simple, convenient way to build [`Label`]s with hard-coded
/// values. It takes a byte slice and returns a label with those contents.
///
/// ```
/// # use domain::new::base::name::{Label, label};
/// #
/// let foo: &'static Label = label!(b"example");
/// assert_eq!(foo.as_wire(), b"\x07example");
///
/// // Escapes in the label are not processed.
/// let foo: &'static Label = label!(b"ex\x0Amp\\e");
/// assert_eq!(foo.as_wire(), b"\x07ex\x0Amp\\e");
///
/// // You can pass non-UTF-8 content.
/// let foo: &'static Label = label!(b"ex\xFFmple");
/// assert_eq!(foo.as_wire(), b"\x07ex\xFFmple");
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! new_base_name_label {
    ($value:literal) => {
        const {
            const BUFFER: &$crate::new::base::name::LabelBuf =
                &$crate::new::base::name::label_buf!($value);
            BUFFER.as_label()
        }
    };
}
pub use crate::new_base_name_label as label;

/// Construct a hard-coded [`LabelBuf`] at compile time.
///
/// This is a convenience function for writing example-based tests; it
/// provides a simple, convenient way to build [`LabelBuf`]s with hard-coded
/// values. It takes a byte slice and returns a label with those contents.
///
/// ```
/// # use domain::new::base::name::{LabelBuf, label_buf};
/// #
/// let foo: LabelBuf = label_buf!(b"example");
/// assert_eq!(foo.as_wire(), b"\x07example");
///
/// // Escapes in the label are not processed.
/// let foo: LabelBuf = label_buf!(b"ex\x0Amp\\e");
/// assert_eq!(foo.as_wire(), b"\x07ex\x0Amp\\e");
///
/// // You can pass non-UTF-8 content.
/// let foo: LabelBuf = label_buf!(b"ex\xFFmple");
/// assert_eq!(foo.as_wire(), b"\x07ex\xFFmple");
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! new_base_name_label_buf {
    ($value:literal) => {
        const {
            let mut buffer = $crate::new::base::name::LabelBuf::new();
            assert!(buffer.append($value).is_ok());
            buffer
        }
    };
}
pub use crate::new_base_name_label_buf as label_buf;

//============ Errors ========================================================

//------------ LabelParseError -----------------------------------------------

/// An error in parsing a [`Label`] from a string.
///
/// This can be returned by [`LabelBuf::from_str()`]. It is not used when
/// parsing labels from the zonefile format, which uses a different mechanism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelParseError {
    /// The label was too large.
    ///
    /// Valid labels are between 1 and 63 bytes, inclusive.
    Overlong,

    /// An invalid character was used.
    ///
    /// Only alphanumeric characters and hyphens are allowed in labels. This
    /// prevents the encoding of perfectly valid labels containing non-ASCII
    /// bytes, but they're fairly rare anyway.
    InvalidChar,

    /// A partial escape was used.
    ///
    /// An escape must be `\\DDD`, where `DDD` are 3 ASCII decimal digits
    /// representing an unsigned 8-bit integer; or `\\X`, where `X` is a
    /// graphical, non-digit ASCII character.
    PartialEscape,

    /// An invalid escape was used.
    ///
    /// An escape must be `\\DDD`, where `DDD` are 3 ASCII decimal digits
    /// representing an unsigned 8-bit integer; or `\\X`, where `X` is a
    /// graphical, non-digit ASCII character.
    InvalidEscape,
}

impl core::error::Error for LabelParseError {}

impl fmt::Display for LabelParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Overlong => "the label was too large",
            Self::InvalidChar => "the label contained an invalid character",
            Self::PartialEscape => "the label contained an incomplete escape",
            Self::InvalidEscape => "the label contained an invalid escape",
        })
    }
}

//------------ LabelSplitError -----------------------------------------------

/// An error in parsing a [`Label`] from a larger string.
///
/// This can be returned by [`LabelBuf::split_str()`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelSplitError {
    /// The label was too large.
    ///
    /// Valid labels are between 1 and 63 bytes, inclusive.
    Overlong,

    /// An invalid character was used.
    ///
    /// Only alphanumeric characters and hyphens are allowed in labels. This
    /// prevents the encoding of perfectly valid labels containing non-ASCII
    /// bytes, but they're fairly rare anyway.
    InvalidChar,

    /// An invalid escape was used.
    ///
    /// An escape must be `\\DDD`, where `DDD` are 3 ASCII decimal digits
    /// representing an unsigned 8-bit integer; or `\\X`, where `X` is a
    /// graphical, non-digit ASCII character.
    InvalidEscape,

    /// The input was too short to parse the label.
    ///
    /// The input did not sufficiently delimit the label. More input (if any)
    /// needs to be collected to correctly parse the entire label.
    ShortInput,
}

impl core::error::Error for LabelSplitError {}

impl fmt::Display for LabelSplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Overlong => "the label was too large",
            Self::InvalidChar => "the label contained an invalid character",
            Self::InvalidEscape => "the label contained an invalid escape",
            Self::ShortInput => "the input was too short to parse the label",
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::Label;

    use crate::new::base::wire::{ParseBytes, ParseError, SplitBytes};

    #[test]
    fn parsing() {
        let good = [
            b"\x00abc" as &[u8],
            b"\x07example\x03org\x00",
            b"\x07f\x00\x00&\x8Fbar-foo",
            b"\x3Fthis is a label of the longest valid length and it's surprising(ly big)",
        ];

        for input in good {
            // Try parsing input with some bytes following it.
            let expected_len = input[0] as usize + 1;
            assert_eq!(<&Label>::parse_bytes(input), Err(ParseError));
            let (actual, rest) = <&Label>::split_bytes(input).unwrap();
            assert_eq!(actual.as_wire().len(), expected_len);
            assert_eq!(actual.as_wire().as_ptr(), input.as_ptr());
            assert_eq!(actual.as_wire().len() + rest.len(), input.len());
            assert_eq!(
                rest.as_ptr(),
                input.as_ptr().wrapping_add(expected_len)
            );

            // Try parsing input that _only_ contains a label.
            let min_input = &input[..expected_len];
            let (actual, rest) = <&Label>::split_bytes(min_input).unwrap();
            assert_eq!(actual.as_wire().as_ptr(), min_input.as_ptr());
            assert_eq!(actual.as_wire().len(), min_input.len());
            assert_eq!(rest, &[] as &[u8]);
            let actual = <&Label>::parse_bytes(min_input).unwrap();
            assert_eq!(actual.as_wire().as_ptr(), min_input.as_ptr());
            assert_eq!(actual.as_wire().len(), min_input.len());

            // Try parsing input that's a byte too short.
            let short_input = &input[..expected_len - 1];
            assert_eq!(<&Label>::split_bytes(short_input), Err(ParseError));
            assert_eq!(<&Label>::parse_bytes(short_input), Err(ParseError));
        }

        let bad = [
            b"\x40this is not a valid label but it would be if 64 was a valid label length" as &[u8],
        ];

        for input in bad {
            assert_eq!(<&Label>::split_bytes(input), Err(ParseError));
            assert_eq!(<&Label>::parse_bytes(input), Err(ParseError));
        }
    }
}
