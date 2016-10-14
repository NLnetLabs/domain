//! A trait for all domain name types.

use std::borrow::Cow;
use super::super::{Composer, ComposeResult};
use super::{DNameSlice, NameLabels, NameLabelettes, RevNameLabels,
            RevNameLabelettes};


//------------ DName ---------------------------------------------------------

/// A trait implemented by all domain name types.
///
/// The purpose of the trait is to allow building composite types that are
/// generic over all possible variants of domain names. In particular,
/// `DName` is implemented for [`&DNameSlice`] for references to uncompressed
/// domain names, [`DNameBuf`] for owned uncompressed domain names, and
/// [`ParsedDName`] for domain names parsed from DNS messages.
///
/// If you don’t need to include [`ParsedDName`], you might want your type
/// to be generic over `AsRef<DNameSlice>` instead as this allows for the
/// full range of functionality provided by [`DNameSlice`].
///
/// [`&DNameSlice`]: struct.DNameSlice.html
/// [`DNameBuf`]: struct.DNameBuf.html
/// [`ParsedDName`]: struct.ParsedDName.html
pub trait DName: Sized {
    /// Converts the name into an uncompressed name.
    ///
    /// Since unpacking parsed domain names may need allocations to collect
    /// the labels, the return value is a cow. This cow will, however, be of
    /// the borrowed variant whenever possible.
    fn to_cow(&self) -> Cow<DNameSlice>;

    /// Returns an iterator over the labels of the domain name.
    fn labels(&self) -> NameLabels;

    /// Returns an iterator over the labels in the name in reverse order.
    ///
    /// Because determining the reverse order is costly, there are two
    /// separate iterator types rather than one single double-ended type.
    fn rev_labels(&self) -> RevNameLabels {
        RevNameLabels::new(self.labels())
    }

    /// Returns an iterator over the labelettes of the domain name.
    ///
    /// See [`Labelette`] for a discussion of what exactly labelettes are.
    ///
    /// [`Labelette`]: struct.Labelette.html
    fn labelettes(&self) -> NameLabelettes {
        NameLabelettes::new(self.labels())
    }

    /// Returns an iterator over the labelettes of the name in reverse order.
    ///
    /// See [`Labelette`] for a discussion of what exactly labelettes are.
    ///
    /// [`Labelette`]: struct.Labelette.html
    fn rev_labelettes(&self) -> RevNameLabelettes {
        RevNameLabelettes::new(self.rev_labels())
    }

    /// Appends the name to the end of a composition.
    fn compose<C: AsMut<Composer>>(&self, mut composer: C)
                                   -> ComposeResult<()> {
        composer.as_mut().compose_dname(self)
    }

    /// Appends the name to the end of a composition using name compression.
    fn compose_compressed<C: AsMut<Composer>>(&self, mut composer: C)
                                              -> ComposeResult<()> {
        composer.as_mut().compose_dname_compressed(self)
    }
}

