//! The Responsible Person record data type.
//!
//! See [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183).

use core::cmp::Ordering;

use crate::new::base::build::{BuildInMessage, NameCompressor};
use crate::new::base::name::CanonicalName;
use crate::new::base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new::base::{
    wire::*, CanonicalRecordData, ParseRecordData, ParseRecordDataBytes,
    RType,
};

//----------- Rp -------------------------------------------------------------

/// Identification of the person/party responsible for this domain.
///
/// An [`Rp`] record identifies the person or party managing a domain. It is
/// a useful backup when standard means of communication fail, e.g. e-mails to
/// `postmaster@` are being dropped due to mail server misconfiguration.
///
/// [`Rp`] is specified by [RFC 1183, section 2].
///
/// [RFC 1183, section 2]: https://datatracker.ietf.org/doc/html/rfc1183#section-2
///
/// ## Wire Format
///
/// The wire format of an [`Rp`] record is the concatenation of its fields,
/// in the same order as the `struct` definition. The domain names within an
/// [`Rp`] may be compressed in DNS messages.
///
/// ## Usage
///
/// Because [`Rp`] is a record data type, it is usually handled within an enum
/// like [`RecordData`]. This section describes how to use it independently
/// (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// In order to build an [`Rp`], it's first important to choose a domain name
/// type. For short-term usage (where the [`Rp`] is a local variable), it is
/// common to pick [`RevNameBuf`]. If the [`Rp`] will be placed on the heap,
/// <code>Box&lt;[`RevName`]&gt;</code> will be more efficient.
///
/// [`RevName`]: crate::new::base::name::RevName
/// [`RevNameBuf`]: crate::new::base::name::RevNameBuf
///
/// The primary way to build a new [`Rp`] is to construct each field manually.
/// To parse a [`Rp`] from a DNS message, use [`ParseMessageBytes`]. In case
/// the input bytes don't use name compression, [`ParseBytes`] can be used.
///
/// ```
/// # use domain::new::base::name::{Name, RevNameBuf};
/// # use domain::new::base::wire::{BuildBytes, ParseBytes, ParseBytesZC};
/// # use domain::new::rdata::Rp;
/// #
/// // Build an 'Rp' manually:
/// let manual: Rp<RevNameBuf> = Rp {
///     mailbox: "postmaster.example.org".parse().unwrap(),
///     texts: "findme.example.org".parse().unwrap(),
/// };
///
/// // Its wire format serialization looks like:
/// let bytes = b"\
///     \x0Apostmaster\x07example\x03org\x00\
///     \x06findme\x07example\x03org\x00";
/// # let mut buffer = [0u8; 44];
/// # manual.build_bytes(&mut buffer).unwrap();
/// # assert_eq!(*bytes, buffer);
///
/// // Parse an 'Rp' from the wire format, without name decompression:
/// let from_wire: Rp<RevNameBuf> = Rp::parse_bytes(bytes).unwrap();
/// # assert_eq!(manual, from_wire);
///
/// // See 'ParseMessageBytes' for parsing with name decompression.
/// ```
///
/// Since [`Rp`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around. However, this depends
/// on the domain name type. It can be changed using [`Rp::map_names()`] and
/// [`Rp::map_names_by_ref()`].
///
/// For debugging, [`Rp`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize an [`Rp`] in the wire format, use [`BuildInMessage`] (which
/// supports name compression). If name compression is not desired, use
/// [`BuildBytes`].
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    BuildBytes,
    ParseBytes,
    SplitBytes,
)]
pub struct Rp<N> {
    /// The mailbox of the responsible person/party.
    ///
    /// This address should lie outside the domain, so that it can be used if
    /// the domain is malfunctioning. It can be used to communicate with the
    /// responsible person/party, similar to the conventional `postmaster@`
    /// address.
    ///
    /// The first label here is the username (i.e. local part) of the e-mail
    /// address, and the remaining labels make up the mail domain name. For
    /// example, <hostmaster@sri-nic.arpa> would be represented as
    /// `hostmaster.sri-nic.arpa`. This convention is specified in [RFC 1034,
    /// section 3.3].
    ///
    /// [RFC 1034, section 3.3]: https://datatracker.ietf.org/doc/html/rfc1034#section-3.3
    ///
    /// This is an optional field; if this field refers to the root domain
    /// (`.`), no mailbox is available.
    pub mailbox: N,

    /// A domain providing [`Txt`] records for human inspection.
    ///
    /// [`Txt`]: crate::new::rdata::Txt
    ///
    /// This should lie outside the name owning the record, so that it can be
    /// used if the domain is malfunctioning. The referenced domain should
    /// provide human-readable [`Txt`] records which explain how to reach the
    /// responsible person/party.
    ///
    /// This is an optional field; if this field refers to the root domain
    /// (`.`), no domain is available.
    pub texts: N,
}

//--- Interaction

impl<N> Rp<N> {
    /// Map the domain names within to another type.
    pub fn map_names<R, F: FnMut(N) -> R>(self, mut f: F) -> Rp<R> {
        Rp {
            mailbox: (f)(self.mailbox),
            texts: (f)(self.texts),
        }
    }

    /// Map references to the domain names within to another type.
    pub fn map_names_by_ref<'r, R, F: FnMut(&'r N) -> R>(
        &'r self,
        mut f: F,
    ) -> Rp<R> {
        Rp {
            mailbox: (f)(&self.mailbox),
            texts: (f)(&self.texts),
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for Rp<N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let bytes = self.mailbox.build_lowercased_bytes(bytes)?;
        let bytes = self.texts.build_lowercased_bytes(bytes)?;
        Ok(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.mailbox
            .cmp_lowercase_composed(&other.mailbox)
            .then_with(|| self.texts.cmp_lowercase_composed(&other.texts))
    }
}

//--- Parsing from DNS messages

impl<'a, N: SplitMessageBytes<'a>> ParseMessageBytes<'a> for Rp<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        let (mailbox, rest) = N::split_message_bytes(contents, start)?;
        let texts = N::parse_message_bytes(contents, rest)?;

        Ok(Self { mailbox, texts })
    }
}

//--- Building into DNS messages

impl<N: BuildInMessage> BuildInMessage for Rp<N> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        start = self.mailbox.build_in_message(contents, start, compressor)?;
        start = self.texts.build_in_message(contents, start, compressor)?;
        Ok(start)
    }
}

//--- Parsing record data

impl<'a, N: SplitMessageBytes<'a>> ParseRecordData<'a> for Rp<N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::RP => Self::parse_message_bytes(contents, start),
            _ => Err(ParseError),
        }
    }
}

impl<'a, N: SplitBytes<'a>> ParseRecordDataBytes<'a> for Rp<N> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::RP => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
