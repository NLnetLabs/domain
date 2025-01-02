//! Procedural macros for [`domain`].
//!
//! [`domain`]: https://docs.rs/domain

use proc_macro as pm;
use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use spanned::Spanned;
use syn::*;

mod impls;
use impls::ImplSkeleton;

mod repr;
use repr::Repr;

//----------- SplitBytes -----------------------------------------------------

#[proc_macro_derive(SplitBytes)]
pub fn derive_split_bytes(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            Data::Struct(data) => data,
            Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'SplitBytes' can only be 'derive'd for 'struct's",
                ));
            }
            Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'SplitBytes' can only be 'derive'd for 'struct's",
                ));
            }
        };

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let bound =
            parse_quote!(::domain::new_base::parse::SplitBytes<'bytes>);
        let mut skeleton = ImplSkeleton::new(&input, false, bound);

        // Add the parsing lifetime to the 'impl'.
        let lifetime = skeleton.new_lifetime("bytes");
        if skeleton.lifetimes.len() > 0 {
            let lifetimes = skeleton.lifetimes.iter();
            let param = parse_quote! {
                #lifetime: #(#lifetimes)+*
            };
            skeleton.lifetimes.push(param);
        } else {
            skeleton.lifetimes.push(parse_quote! { #lifetime })
        }

        // Establish bounds on the fields.
        for field in data.fields.iter() {
            skeleton.require_bound(
                field.ty.clone(),
                parse_quote!(::domain::new_base::parse::SplitBytes<#lifetime>),
            );
        }

        // Construct a 'Self' expression.
        let self_expr = match &data.fields {
            Fields::Named(_) => {
                let names = data.fields.members();
                let exprs =
                    names.clone().map(|n| format_ident!("field_{}", n));
                quote! {
                    Self {
                        #(#names: #exprs,)*
                    }
                }
            }

            Fields::Unnamed(_) => {
                let exprs = data
                    .fields
                    .members()
                    .map(|n| format_ident!("field_{}", n));
                quote! {
                    Self(#(#exprs,)*)
                }
            }

            Fields::Unit => quote! { Self },
        };

        // Define 'parse_bytes()'.
        let names =
            data.fields.members().map(|n| format_ident!("field_{}", n));
        let tys = data.fields.iter().map(|f| &f.ty);
        skeleton.contents.stmts.push(parse_quote! {
            fn split_bytes(
                bytes: & #lifetime [::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                (Self, & #lifetime [::domain::__core::primitive::u8]),
                ::domain::new_base::parse::ParseError,
            > {
                #(let (#names, bytes) =
                    <#tys as ::domain::new_base::parse::SplitBytes<#lifetime>>
                    ::split_bytes(bytes)?;)*
                Ok((#self_expr, bytes))
            }
        });

        Ok(skeleton.into_token_stream().into())
    }

    let input = syn::parse_macro_input!(input as DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

//----------- ParseBytes -----------------------------------------------------

#[proc_macro_derive(ParseBytes)]
pub fn derive_parse_bytes(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            Data::Struct(data) => data,
            Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'ParseBytes' can only be 'derive'd for 'struct's",
                ));
            }
            Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'ParseBytes' can only be 'derive'd for 'struct's",
                ));
            }
        };

        // Split up the last field from the rest.
        let mut fields = data.fields.iter();
        let Some(last) = fields.next_back() else {
            // This type has no fields.  Return a simple implementation.
            assert!(input.generics.params.is_empty());
            let where_clause = input.generics.where_clause;
            let name = input.ident;

            // This will tokenize to '{}', '()', or ''.
            let fields = data.fields.to_token_stream();

            return Ok(quote! {
                impl <'bytes>
                ::domain::new_base::parse::ParseBytes<'bytes>
                for #name
                #where_clause {
                    fn parse_bytes(
                        bytes: &'bytes [::domain::__core::primitive::u8],
                    ) -> ::domain::__core::result::Result<
                        Self,
                        ::domain::new_base::parse::ParseError,
                    > {
                        if bytes.is_empty() {
                            Ok(Self #fields)
                        } else {
                            Err()
                        }
                    }
                }
            });
        };

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let bound =
            parse_quote!(::domain::new_base::parse::ParseBytes<'bytes>);
        let mut skeleton = ImplSkeleton::new(&input, false, bound);

        // Add the parsing lifetime to the 'impl'.
        let lifetime = skeleton.new_lifetime("bytes");
        if skeleton.lifetimes.len() > 0 {
            let lifetimes = skeleton.lifetimes.iter();
            let param = parse_quote! {
                #lifetime: #(#lifetimes)+*
            };
            skeleton.lifetimes.push(param);
        } else {
            skeleton.lifetimes.push(parse_quote! { #lifetime })
        }

        // Establish bounds on the fields.
        for field in fields.clone() {
            // This field should implement 'SplitBytes'.
            skeleton.require_bound(
                field.ty.clone(),
                parse_quote!(::domain::new_base::parse::SplitBytes<#lifetime>),
            );
        }
        // The last field should implement 'ParseBytes'.
        skeleton.require_bound(
            last.ty.clone(),
            parse_quote!(::domain::new_base::parse::ParseBytes<#lifetime>),
        );

        // Construct a 'Self' expression.
        let self_expr = match &data.fields {
            Fields::Named(_) => {
                let names = data.fields.members();
                let exprs =
                    names.clone().map(|n| format_ident!("field_{}", n));
                quote! {
                    Self {
                        #(#names: #exprs,)*
                    }
                }
            }

            Fields::Unnamed(_) => {
                let exprs = data
                    .fields
                    .members()
                    .map(|n| format_ident!("field_{}", n));
                quote! {
                    Self(#(#exprs,)*)
                }
            }

            Fields::Unit => unreachable!(),
        };

        // Define 'parse_bytes()'.
        let names = data
            .fields
            .members()
            .take(fields.len())
            .map(|n| format_ident!("field_{}", n));
        let tys = fields.clone().map(|f| &f.ty);
        let last_ty = &last.ty;
        let last_name =
            format_ident!("field_{}", data.fields.members().last().unwrap());
        skeleton.contents.stmts.push(parse_quote! {
            fn parse_bytes(
                bytes: & #lifetime [::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                Self,
                ::domain::new_base::parse::ParseError,
            > {
                #(let (#names, bytes) =
                    <#tys as ::domain::new_base::parse::SplitBytes<#lifetime>>
                    ::split_bytes(bytes)?;)*
                let #last_name =
                    <#last_ty as ::domain::new_base::parse::ParseBytes<#lifetime>>
                    ::parse_bytes(bytes)?;
                Ok(#self_expr)
            }
        });

        Ok(skeleton.into_token_stream().into())
    }

    let input = syn::parse_macro_input!(input as DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

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
                        if bytes.is_empty() {
                            // SAFETY: 'Self' is a 'struct' with no fields,
                            // and so has size 0 and alignment 1.  It can be
                            // constructed at any address.
                            Ok(unsafe { &*bytes.as_ptr().cast::<Self>() })
                        } else {
                            Err(::domain::new_base::parse::ParseError)
                        }
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
