//! Procedural macros for [`domain`].
//!
//! [`domain`]: https://docs.rs/domain

use proc_macro as pm;
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use spanned::Spanned;
use syn::*;

mod impls;
use impls::ImplSkeleton;

mod repr;
use repr::Repr;

//----------- SplitBytesByRef ------------------------------------------------

#[proc_macro_derive(SplitBytesByRef)]
pub fn derive_split_bytes_by_ref(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            Data::Struct(data) => data,
            Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'SplitBytesByRef' can only be 'derive'd for 'struct's",
                ));
            }
            Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'SplitBytesByRef' can only be 'derive'd for 'struct's",
                ));
            }
        };

        let _ = Repr::determine(&input.attrs, "SplitBytesByRef")?;

        // Split up the last field from the rest.
        let mut fields = data.fields.iter();
        let Some(last) = fields.next_back() else {
            // This type has no fields.  Return a simple implementation.
            let (impl_generics, ty_generics, where_clause) =
                input.generics.split_for_impl();
            let name = input.ident;

            return Ok(quote! {
                unsafe impl #impl_generics
                ::domain::new_base::parse::SplitBytesByRef
                for #name #ty_generics
                #where_clause {
                    fn split_bytes_by_ref(
                        bytes: &[::domain::__core::primitive::u8],
                    ) -> ::domain::__core::result::Result<
                        (&Self, &[::domain::__core::primitive::u8]),
                        ::domain::new_base::parse::ParseError,
                    > {
                        Ok((
                            unsafe { &*bytes.as_ptr().cast::<Self>() },
                            bytes,
                        ))
                    }
                }
            });
        };

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let bound = parse_quote!(::domain::new_base::parse::SplitBytesByRef);
        let mut skeleton = ImplSkeleton::new(&input, true, bound);

        // Establish bounds on the fields.
        for field in data.fields.iter() {
            skeleton.require_bound(
                field.ty.clone(),
                parse_quote!(::domain::new_base::parse::SplitBytesByRef),
            );
        }

        // Define 'split_bytes_by_ref()'.
        let tys = fields.clone().map(|f| &f.ty);
        let last_ty = &last.ty;
        skeleton.contents.stmts.push(parse_quote! {
            fn split_bytes_by_ref(
                bytes: &[::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                (&Self, &[::domain::__core::primitive::u8]),
                ::domain::new_base::parse::ParseError,
            > {
                let start = bytes.as_ptr();
                #(let (_, bytes) =
                    <#tys as ::domain::new_base::parse::SplitBytesByRef>
                    ::split_bytes_by_ref(bytes)?;)*
                let (last, rest) =
                    <#last_ty as ::domain::new_base::parse::SplitBytesByRef>
                    ::split_bytes_by_ref(bytes)?;
                let ptr =
                    <#last_ty as ::domain::new_base::parse::ParseBytesByRef>
                    ::ptr_with_address(last, start as *const ());

                // SAFETY:
                // - The original 'bytes' contained a valid instance of every
                //   field in 'Self', in succession.
                // - Every field implements 'ParseBytesByRef' and so has no
                //   alignment restriction.
                // - 'Self' is unaligned, since every field is unaligned, and
                //   any explicit alignment modifiers only make it unaligned.
                // - 'start' is thus the start of a valid instance of 'Self'.
                // - 'ptr' has the same address as 'start' but can be cast to
                //   'Self', since it has the right pointer metadata.
                Ok((unsafe { &*(ptr as *const Self) }, rest))
            }
        });

        Ok(skeleton.into_token_stream().into())
    }

    let input = syn::parse_macro_input!(input as DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

//----------- ParseBytesByRef ------------------------------------------------

#[proc_macro_derive(ParseBytesByRef)]
pub fn derive_parse_bytes_by_ref(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
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

        let _ = Repr::determine(&input.attrs, "ParseBytesByRef")?;

        // Split up the last field from the rest.
        let mut fields = data.fields.iter();
        let Some(last) = fields.next_back() else {
            // This type has no fields.  Return a simple implementation.
            let (impl_generics, ty_generics, where_clause) =
                input.generics.split_for_impl();
            let name = input.ident;

            return Ok(quote! {
                unsafe impl #impl_generics
                ::domain::new_base::parse::ParseBytesByRef
                for #name #ty_generics
                #where_clause {
                    fn parse_bytes_by_ref(
                        bytes: &[::domain::__core::primitive::u8],
                    ) -> ::domain::__core::result::Result<
                        &Self,
                        ::domain::new_base::parse::ParseError,
                    > {
                        Ok(unsafe { &*bytes.as_ptr().cast::<Self>() })
                    }

                    fn ptr_with_address(
                        &self,
                        addr: *const (),
                    ) -> *const Self {
                        addr.cast()
                    }
                }
            });
        };

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let bound = parse_quote!(::domain::new_base::parse::ParseBytesByRef);
        let mut skeleton = ImplSkeleton::new(&input, true, bound);

        // Establish bounds on the fields.
        for field in fields.clone() {
            // This field should implement 'SplitBytesByRef'.
            skeleton.require_bound(
                field.ty.clone(),
                parse_quote!(::domain::new_base::parse::SplitBytesByRef),
            );
        }
        // The last field should implement 'ParseBytesByRef'.
        skeleton.require_bound(
            last.ty.clone(),
            parse_quote!(::domain::new_base::parse::ParseBytesByRef),
        );

        // Define 'parse_bytes_by_ref()'.
        let tys = fields.clone().map(|f| &f.ty);
        let last_ty = &last.ty;
        skeleton.contents.stmts.push(parse_quote! {
            fn parse_bytes_by_ref(
                bytes: &[::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                &Self,
                ::domain::new_base::parse::ParseError,
            > {
                let start = bytes.as_ptr();
                #(let (_, bytes) =
                    <#tys as ::domain::new_base::parse::SplitBytesByRef>
                    ::split_bytes_by_ref(bytes)?;)*
                let last =
                    <#last_ty as ::domain::new_base::parse::ParseBytesByRef>
                    ::parse_bytes_by_ref(bytes)?;
                let ptr =
                    <#last_ty as ::domain::new_base::parse::ParseBytesByRef>
                    ::ptr_with_address(last, start as *const ());

                // SAFETY:
                // - The original 'bytes' contained a valid instance of every
                //   field in 'Self', in succession.
                // - Every field implements 'ParseBytesByRef' and so has no
                //   alignment restriction.
                // - 'Self' is unaligned, since every field is unaligned, and
                //   any explicit alignment modifiers only make it unaligned.
                // - 'start' is thus the start of a valid instance of 'Self'.
                // - 'ptr' has the same address as 'start' but can be cast to
                //   'Self', since it has the right pointer metadata.
                Ok(unsafe { &*(ptr as *const Self) })
            }
        });

        // Define 'ptr_with_address()'.
        let last_name = match last.ident.as_ref() {
            Some(ident) => Member::Named(ident.clone()),
            None => Member::Unnamed(Index {
                index: data.fields.len() as u32 - 1,
                span: last.ty.span(),
            }),
        };
        skeleton.contents.stmts.push(parse_quote! {
            fn ptr_with_address(&self, addr: *const ()) -> *const Self {
                <#last_ty as ::domain::new_base::parse::ParseBytesByRef>
                    ::ptr_with_address(&self.#last_name, addr)
                    as *const Self
            }
        });

        Ok(skeleton.into_token_stream().into())
    }

    let input = syn::parse_macro_input!(input as DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
