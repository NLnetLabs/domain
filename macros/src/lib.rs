//! Procedural macros for [`domain`].
//!
//! [`domain`]: https://docs.rs/domain

use proc_macro as pm;
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::*;

mod impls;
use impls::ImplSkeleton;

//----------- ParseBytesByRef ------------------------------------------------

#[proc_macro_derive(ParseBytesByRef)]
pub fn derive_parse_bytes_by_ref(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: DeriveInput) -> Result<TokenStream> {
        let bound = parse_quote!(::domain::new_base::parse::ParseBytesByRef);
        let mut skeleton = ImplSkeleton::new(&input, true, bound);

        let data = match input.data {
            Data::Struct(data) => data,
            Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'ParseBytesByRef' can only be 'derive'd for 'struct's",
                ));
            }
            Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'ParseBytesByRef' can only be 'derive'd for 'struct's",
                ));
            }
        };

        // TODO: Ensure that the type is 'repr(C)' or 'repr(transparent)'.

        // Every field must implement 'ParseBytesByRef'.
        for field in data.fields.iter() {
            let bound =
                parse_quote!(::domain::new_base::parse::ParseBytesByRef);
            skeleton.require_bound(field.ty.clone(), bound);
        }

        // TODO: Implement 'parse_bytes_by_ref()' in 'skeleton.contents'.

        Ok(skeleton.into_token_stream().into())
    }

    let input = syn::parse_macro_input!(input as DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
