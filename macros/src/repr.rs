//! Determining the memory layout of a type.

use proc_macro2::Span;
use syn::{punctuated::Punctuated, *};

//----------- Repr -----------------------------------------------------------

/// The memory representation of a type.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Repr {
    /// Transparent to an underlying field.
    Transparent,

    /// Compatible with C.
    C,
}

impl Repr {
    /// Determine the representation for a type from its attributes.
    ///
    /// This will fail if a stable representation cannot be found.
    pub fn determine(attrs: &[Attribute]) -> Result<Self> {
        let mut repr = None;
        for attr in attrs {
            if !attr.path().is_ident("repr") {
                continue;
            }

            let nested = attr.parse_args_with(
                Punctuated::<Meta, Token![,]>::parse_terminated,
            )?;

            // We don't check for consistency in the 'repr' attributes, since
            // the compiler should be doing that for us anyway.  This lets us
            // ignore conflicting 'repr's entirely.
            for meta in nested {
                match meta {
                    Meta::Path(p) if p.is_ident("transparent") => {
                        repr = Some(Repr::Transparent);
                    }

                    Meta::Path(p) if p.is_ident("C") => {
                        repr = Some(Repr::C);
                    }

                    Meta::Path(p) if p.is_ident("Rust") => {
                        return Err(Error::new_spanned(p,
                            "repr(Rust) is not stable, cannot derive this for it"));
                    }

                    meta => {
                        // We still need to error out here, in case a future
                        // version of Rust introduces more memory layout data
                        return Err(Error::new_spanned(
                            meta,
                            "unrecognized repr attribute",
                        ));
                    }
                }
            }
        }

        repr.ok_or_else(|| {
            Error::new(Span::call_site(),
                "repr(C) or repr(transparent) must be specified to derive this")
        })
    }
}
