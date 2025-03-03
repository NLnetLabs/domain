//! Procedural macros for [`domain`].
//!
//! [`domain`]: https://docs.rs/domain

use proc_macro as pm;
use proc_macro2::TokenStream;
use quote::{format_ident, ToTokens};
use syn::{Error, Ident, Result};

mod impls;
use impls::ImplSkeleton;

mod data;
use data::Struct;

mod repr;
use repr::Repr;

//----------- SplitBytes -----------------------------------------------------

#[proc_macro_derive(SplitBytes)]
pub fn derive_split_bytes(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: syn::DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            syn::Data::Struct(data) => data,
            syn::Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'SplitBytes' can only be 'derive'd for 'struct's",
                ));
            }
            syn::Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'SplitBytes' can only be 'derive'd for 'struct's",
                ));
            }
        };

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let mut skeleton = ImplSkeleton::new(&input, false);

        // Add the parsing lifetime to the 'impl'.
        let (lifetime, param) = skeleton.new_lifetime_param(
            "bytes",
            skeleton.lifetimes.iter().map(|l| l.lifetime.clone()),
        );
        skeleton.lifetimes.push(param);
        skeleton.bound = Some(
            syn::parse_quote!(::domain::new_base::wire::SplitBytes<#lifetime>),
        );

        // Inspect the 'struct' fields.
        let data = Struct::new_as_self(&data.fields);
        let builder = data.builder(field_prefixed);

        // Establish bounds on the fields.
        for field in data.fields() {
            skeleton.require_bound(
                field.ty.clone(),
                syn::parse_quote!(::domain::new_base::wire::SplitBytes<#lifetime>),
            );
        }

        // Define 'parse_bytes()'.
        let init_vars = builder.init_vars();
        let tys = data.fields().map(|f| &f.ty);
        skeleton.contents.stmts.push(syn::parse_quote! {
            fn split_bytes(
                bytes: & #lifetime [::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                (Self, & #lifetime [::domain::__core::primitive::u8]),
                ::domain::new_base::wire::ParseError,
            > {
                #(let (#init_vars, bytes) =
                    <#tys as ::domain::new_base::wire::SplitBytes<#lifetime>>
                    ::split_bytes(bytes)?;)*
                Ok((#builder, bytes))
            }
        });

        Ok(skeleton.into_token_stream())
    }

    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

//----------- ParseBytes -----------------------------------------------------

#[proc_macro_derive(ParseBytes)]
pub fn derive_parse_bytes(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: syn::DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            syn::Data::Struct(data) => data,
            syn::Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'ParseBytes' can only be 'derive'd for 'struct's",
                ));
            }
            syn::Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'ParseBytes' can only be 'derive'd for 'struct's",
                ));
            }
        };

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let mut skeleton = ImplSkeleton::new(&input, false);

        // Add the parsing lifetime to the 'impl'.
        let (lifetime, param) = skeleton.new_lifetime_param(
            "bytes",
            skeleton.lifetimes.iter().map(|l| l.lifetime.clone()),
        );
        skeleton.lifetimes.push(param);
        skeleton.bound = Some(
            syn::parse_quote!(::domain::new_base::wire::ParseBytes<#lifetime>),
        );

        // Inspect the 'struct' fields.
        let data = Struct::new_as_self(&data.fields);
        let builder = data.builder(field_prefixed);

        // Establish bounds on the fields.
        for field in data.sized_fields() {
            skeleton.require_bound(
                field.ty.clone(),
                syn::parse_quote!(::domain::new_base::wire::SplitBytes<#lifetime>),
            );
        }
        if let Some(field) = data.unsized_field() {
            skeleton.require_bound(
                field.ty.clone(),
                syn::parse_quote!(::domain::new_base::wire::ParseBytes<#lifetime>),
            );
        }

        // Finish early if the 'struct' has no fields.
        if data.is_empty() {
            skeleton.contents.stmts.push(syn::parse_quote! {
                fn parse_bytes(
                    bytes: & #lifetime [::domain::__core::primitive::u8],
                ) -> ::domain::__core::result::Result<
                    Self,
                    ::domain::new_base::wire::ParseError,
                > {
                    if bytes.is_empty() {
                        Ok(#builder)
                    } else {
                        Err(::domain::new_base::wire::ParseError)
                    }
                }
            });

            return Ok(skeleton.into_token_stream());
        }

        // Define 'parse_bytes()'.
        let init_vars = builder.sized_init_vars();
        let tys = builder.sized_fields().map(|f| &f.ty);
        let unsized_ty = &builder.unsized_field().unwrap().ty;
        let unsized_init_var = builder.unsized_init_var().unwrap();
        skeleton.contents.stmts.push(syn::parse_quote! {
            fn parse_bytes(
                bytes: & #lifetime [::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                Self,
                ::domain::new_base::wire::ParseError,
            > {
                #(let (#init_vars, bytes) =
                    <#tys as ::domain::new_base::wire::SplitBytes<#lifetime>>
                    ::split_bytes(bytes)?;)*
                let #unsized_init_var =
                    <#unsized_ty as ::domain::new_base::wire::ParseBytes<#lifetime>>
                    ::parse_bytes(bytes)?;
                Ok(#builder)
            }
        });

        Ok(skeleton.into_token_stream())
    }

    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

//----------- SplitBytesByRef ------------------------------------------------

#[proc_macro_derive(SplitBytesByRef)]
pub fn derive_split_bytes_by_ref(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: syn::DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            syn::Data::Struct(data) => data,
            syn::Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'SplitBytesByRef' can only be 'derive'd for 'struct's",
                ));
            }
            syn::Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'SplitBytesByRef' can only be 'derive'd for 'struct's",
                ));
            }
        };

        let _ = Repr::determine(&input.attrs, "SplitBytesByRef")?;

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let mut skeleton = ImplSkeleton::new(&input, true);
        skeleton.bound = Some(syn::parse_quote!(
            ::domain::new_base::wire::SplitBytesByRef
        ));

        // Inspect the 'struct' fields.
        let data = Struct::new_as_self(&data.fields);

        // Establish bounds on the fields.
        for field in data.fields() {
            skeleton.require_bound(
                field.ty.clone(),
                syn::parse_quote!(::domain::new_base::wire::SplitBytesByRef),
            );
        }

        // Finish early if the 'struct' has no fields.
        if data.is_empty() {
            skeleton.contents.stmts.push(syn::parse_quote! {
                fn split_bytes_by_ref(
                    bytes: &[::domain::__core::primitive::u8],
                ) -> ::domain::__core::result::Result<
                    (&Self, &[::domain::__core::primitive::u8]),
                    ::domain::new_base::wire::ParseError,
                > {
                    Ok((
                        // SAFETY: 'Self' is a 'struct' with no fields,
                        // and so has size 0 and alignment 1.  It can be
                        // constructed at any address.
                        unsafe { &*bytes.as_ptr().cast::<Self>() },
                        bytes,
                    ))
                }
            });

            return Ok(skeleton.into_token_stream());
        }

        // Define 'split_bytes_by_ref()'.
        let tys = data.sized_fields().map(|f| &f.ty);
        let unsized_ty = &data.unsized_field().unwrap().ty;
        skeleton.contents.stmts.push(syn::parse_quote! {
            fn split_bytes_by_ref(
                bytes: &[::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                (&Self, &[::domain::__core::primitive::u8]),
                ::domain::new_base::wire::ParseError,
            > {
                let start = bytes.as_ptr();
                #(let (_, bytes) =
                    <#tys as ::domain::new_base::wire::SplitBytesByRef>
                    ::split_bytes_by_ref(bytes)?;)*
                let (last, rest) =
                    <#unsized_ty as ::domain::new_base::wire::SplitBytesByRef>
                    ::split_bytes_by_ref(bytes)?;
                let ptr =
                    <#unsized_ty as ::domain::new_base::wire::ParseBytesByRef>
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

        // Define 'split_bytes_by_mut()'.
        let tys = data.sized_fields().map(|f| &f.ty);
        skeleton.contents.stmts.push(syn::parse_quote! {
            fn split_bytes_by_mut(
                bytes: &mut [::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                (&mut Self, &mut [::domain::__core::primitive::u8]),
                ::domain::new_base::wire::ParseError,
            > {
                let start = bytes.as_ptr();
                #(let (_, bytes) =
                    <#tys as ::domain::new_base::wire::SplitBytesByRef>
                    ::split_bytes_by_mut(bytes)?;)*
                let (last, rest) =
                    <#unsized_ty as ::domain::new_base::wire::SplitBytesByRef>
                    ::split_bytes_by_mut(bytes)?;
                let ptr =
                    <#unsized_ty as ::domain::new_base::wire::ParseBytesByRef>
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
                Ok((unsafe { &mut *(ptr as *const Self as *mut Self) }, rest))
            }
        });

        Ok(skeleton.into_token_stream())
    }

    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

//----------- ParseBytesByRef ------------------------------------------------

#[proc_macro_derive(ParseBytesByRef)]
pub fn derive_parse_bytes_by_ref(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: syn::DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            syn::Data::Struct(data) => data,
            syn::Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'ParseBytesByRef' can only be 'derive'd for 'struct's",
                ));
            }
            syn::Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'ParseBytesByRef' can only be 'derive'd for 'struct's",
                ));
            }
        };

        let _ = Repr::determine(&input.attrs, "ParseBytesByRef")?;

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let mut skeleton = ImplSkeleton::new(&input, true);
        skeleton.bound = Some(syn::parse_quote!(
            ::domain::new_base::wire::ParseBytesByRef
        ));

        // Inspect the 'struct' fields.
        let data = Struct::new_as_self(&data.fields);

        // Establish bounds on the fields.
        for field in data.sized_fields() {
            skeleton.require_bound(
                field.ty.clone(),
                syn::parse_quote!(::domain::new_base::wire::SplitBytesByRef),
            );
        }
        if let Some(field) = data.unsized_field() {
            skeleton.require_bound(
                field.ty.clone(),
                syn::parse_quote!(::domain::new_base::wire::ParseBytesByRef),
            );
        }

        // Finish early if the 'struct' has no fields.
        if data.is_empty() {
            skeleton.contents.stmts.push(syn::parse_quote! {
                fn parse_bytes_by_ref(
                    bytes: &[::domain::__core::primitive::u8],
                ) -> ::domain::__core::result::Result<
                    &Self,
                    ::domain::new_base::wire::ParseError,
                > {
                    if bytes.is_empty() {
                        // SAFETY: 'Self' is a 'struct' with no fields,
                        // and so has size 0 and alignment 1.  It can be
                        // constructed at any address.
                        Ok(unsafe { &*bytes.as_ptr().cast::<Self>() })
                    } else {
                        Err(::domain::new_base::wire::ParseError)
                    }
                }
            });

            skeleton.contents.stmts.push(syn::parse_quote! {
                fn ptr_with_address(
                    &self,
                    addr: *const (),
                ) -> *const Self {
                    addr.cast()
                }
            });

            return Ok(skeleton.into_token_stream());
        }

        // Define 'parse_bytes_by_ref()'.
        let tys = data.sized_fields().map(|f| &f.ty);
        let unsized_ty = &data.unsized_field().unwrap().ty;
        skeleton.contents.stmts.push(syn::parse_quote! {
            fn parse_bytes_by_ref(
                bytes: &[::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                &Self,
                ::domain::new_base::wire::ParseError,
            > {
                let start = bytes.as_ptr();
                #(let (_, bytes) =
                    <#tys as ::domain::new_base::wire::SplitBytesByRef>
                    ::split_bytes_by_ref(bytes)?;)*
                let last =
                    <#unsized_ty as ::domain::new_base::wire::ParseBytesByRef>
                    ::parse_bytes_by_ref(bytes)?;
                let ptr =
                    <#unsized_ty as ::domain::new_base::wire::ParseBytesByRef>
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

        // Define 'parse_bytes_by_mut()'.
        let tys = data.sized_fields().map(|f| &f.ty);
        skeleton.contents.stmts.push(syn::parse_quote! {
            fn parse_bytes_by_mut(
                bytes: &mut [::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                &mut Self,
                ::domain::new_base::wire::ParseError,
            > {
                let start = bytes.as_ptr();
                #(let (_, bytes) =
                    <#tys as ::domain::new_base::wire::SplitBytesByRef>
                    ::split_bytes_by_mut(bytes)?;)*
                let last =
                    <#unsized_ty as ::domain::new_base::wire::ParseBytesByRef>
                    ::parse_bytes_by_mut(bytes)?;
                let ptr =
                    <#unsized_ty as ::domain::new_base::wire::ParseBytesByRef>
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
                Ok(unsafe { &mut *(ptr as *const Self as *mut Self) })
            }
        });

        // Define 'ptr_with_address()'.
        let unsized_member = data.unsized_member();
        skeleton.contents.stmts.push(syn::parse_quote! {
            fn ptr_with_address(&self, addr: *const ()) -> *const Self {
                <#unsized_ty as ::domain::new_base::wire::ParseBytesByRef>
                    ::ptr_with_address(&self.#unsized_member, addr)
                    as *const Self
            }
        });

        Ok(skeleton.into_token_stream())
    }

    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

//----------- BuildBytes -----------------------------------------------------

#[proc_macro_derive(BuildBytes)]
pub fn derive_build_bytes(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: syn::DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            syn::Data::Struct(data) => data,
            syn::Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'BuildBytes' can only be 'derive'd for 'struct's",
                ));
            }
            syn::Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'BuildBytes' can only be 'derive'd for 'struct's",
                ));
            }
        };

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let mut skeleton = ImplSkeleton::new(&input, false);
        skeleton.bound =
            Some(syn::parse_quote!(::domain::new_base::wire::BuildBytes));

        // Inspect the 'struct' fields.
        let data = Struct::new_as_self(&data.fields);

        // Get a lifetime for the input buffer.
        let lifetime = skeleton.new_lifetime("bytes");

        // Establish bounds on the fields.
        for field in data.fields() {
            skeleton.require_bound(
                field.ty.clone(),
                syn::parse_quote!(::domain::new_base::wire::BuildBytes),
            );
        }

        // Define 'build_bytes()'.
        let members = data.members();
        let tys = data.fields().map(|f| &f.ty);
        skeleton.contents.stmts.push(syn::parse_quote! {
            fn build_bytes<#lifetime>(
                &self,
                mut bytes: & #lifetime mut [::domain::__core::primitive::u8],
            ) -> ::domain::__core::result::Result<
                & #lifetime mut [::domain::__core::primitive::u8],
                ::domain::new_base::wire::TruncationError,
            > {
                #(bytes = <#tys as ::domain::new_base::wire::BuildBytes>
                    ::build_bytes(&self.#members, bytes)?;)*
                Ok(bytes)
            }
        });

        Ok(skeleton.into_token_stream())
    }

    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

//----------- AsBytes --------------------------------------------------------

#[proc_macro_derive(AsBytes)]
pub fn derive_as_bytes(input: pm::TokenStream) -> pm::TokenStream {
    fn inner(input: syn::DeriveInput) -> Result<TokenStream> {
        let data = match &input.data {
            syn::Data::Struct(data) => data,
            syn::Data::Enum(data) => {
                return Err(Error::new_spanned(
                    data.enum_token,
                    "'AsBytes' can only be 'derive'd for 'struct's",
                ));
            }
            syn::Data::Union(data) => {
                return Err(Error::new_spanned(
                    data.union_token,
                    "'AsBytes' can only be 'derive'd for 'struct's",
                ));
            }
        };

        let _ = Repr::determine(&input.attrs, "AsBytes")?;

        // Construct an 'ImplSkeleton' so that we can add trait bounds.
        let mut skeleton = ImplSkeleton::new(&input, true);
        skeleton.bound =
            Some(syn::parse_quote!(::domain::new_base::wire::AsBytes));

        // Establish bounds on the fields.
        for field in data.fields.iter() {
            skeleton.require_bound(
                field.ty.clone(),
                syn::parse_quote!(::domain::new_base::wire::AsBytes),
            );
        }

        // The default implementation of 'as_bytes()' works perfectly.

        Ok(skeleton.into_token_stream())
    }

    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    inner(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

//----------- Utility Functions ----------------------------------------------

/// Add a `field_` prefix to member names.
fn field_prefixed(member: syn::Member) -> Ident {
    format_ident!("field_{}", member)
}
