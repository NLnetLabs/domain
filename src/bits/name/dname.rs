//! The DName trait.

use std::borrow::Cow;
use std::fmt;
use super::super::{Composer, ComposeResult};
use super::{DNameSlice, NameIter, NameLabelettes, RevNameIter,
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
pub trait DName: fmt::Debug + fmt::Display + Sized {
    /// Converts the name into an uncompressed name.
    ///
    /// Since unpacking parsed domain names may need allocations to collect
    /// the labels, the return value is a cow. This cow will, however, be of
    /// the borrowed variant whenever possible.
    fn to_cow(&self) -> Cow<DNameSlice>;

    /// Returns an iterator over the labels of the domain name.
    fn labels(&self) -> NameIter;

    fn rev_labels(&self) -> RevNameIter {
        RevNameIter::new(self.labels())
    }

    fn labelettes(&self) -> NameLabelettes {
        NameLabelettes::new(self.labels())
    }

    fn rev_labelettes(&self) -> RevNameLabelettes {
        RevNameLabelettes::new(self.rev_labels())
    }

    fn compose<C: AsMut<Composer>>(&self, mut composer: C)
                                   -> ComposeResult<()> {
        composer.as_mut().compose_dname(self)
    }

    fn compose_compressed<C: AsMut<Composer>>(&self, mut composer: C)
                                              -> ComposeResult<()> {
        composer.as_mut().compose_dname_compressed(self)
    }
}

