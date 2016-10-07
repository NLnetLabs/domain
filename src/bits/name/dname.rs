//! The DName trait.

use std::borrow::Cow;
use std::fmt;
use super::super::{Composer, ComposeResult};
use super::{DNameSlice, NameIter, NameLabelettes, RevNameIter,
            RevNameLabelettes};


//------------ DName ---------------------------------------------------------

pub trait DName: fmt::Debug + fmt::Display + Sized {
    fn to_cow(&self) -> Cow<DNameSlice>;
    fn iter(&self) -> NameIter;

    fn rev_iter(&self) -> RevNameIter {
        RevNameIter::new(self.iter())
    }

    fn labelettes(&self) -> NameLabelettes {
        NameLabelettes::new(self.iter())
    }

    fn rev_labelettes(&self) -> RevNameLabelettes {
        RevNameLabelettes::new(self.rev_iter())
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

