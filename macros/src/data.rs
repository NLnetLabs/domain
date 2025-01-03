//! Working with structs, enums, and unions.

use std::ops::Deref;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{spanned::Spanned, *};

//----------- Struct ---------------------------------------------------------

/// A defined 'struct'.
pub struct Struct {
    /// The identifier for this 'struct'.
    ident: Ident,

    /// The fields in this 'struct'.
    fields: Fields,
}

impl Struct {
    /// Construct a [`Struct`] for a 'Self'.
    pub fn new_as_self(fields: &Fields) -> Self {
        Self {
            ident: <Token![Self]>::default().into(),
            fields: fields.clone(),
        }
    }

    /// Whether this 'struct' has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The number of fields in this 'struct'.
    pub fn num_fields(&self) -> usize {
        self.fields.len()
    }

    /// The fields of this 'struct'.
    pub fn fields(&self) -> impl Iterator<Item = &Field> + '_ {
        self.fields.iter()
    }

    /// The sized fields of this 'struct'.
    pub fn sized_fields(&self) -> impl Iterator<Item = &Field> + '_ {
        self.fields().take(self.num_fields() - 1)
    }

    /// The unsized field of this 'struct'.
    pub fn unsized_field(&self) -> Option<&Field> {
        self.fields.iter().next_back()
    }

    /// The names of the fields of this 'struct'.
    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.fields
            .iter()
            .enumerate()
            .map(|(i, f)| make_member(i, f))
    }

    /// The names of the sized fields of this 'struct'.
    pub fn sized_members(&self) -> impl Iterator<Item = Member> + '_ {
        self.members().take(self.num_fields() - 1)
    }

    /// The name of the last field of this 'struct'.
    pub fn unsized_member(&self) -> Option<Member> {
        self.fields
            .iter()
            .next_back()
            .map(|f| make_member(self.num_fields() - 1, f))
    }

    /// Construct a builder for this 'struct'.
    pub fn builder<F: Fn(Member) -> Ident>(
        &self,
        f: F,
    ) -> StructBuilder<'_, F> {
        StructBuilder {
            target: self,
            var_fn: f,
        }
    }
}

/// Construct a [`Member`] from a field and index.
fn make_member(index: usize, field: &Field) -> Member {
    match &field.ident {
        Some(ident) => Member::Named(ident.clone()),
        None => Member::Unnamed(Index {
            index: index as u32,
            span: field.ty.span(),
        }),
    }
}

//----------- StructBuilder --------------------------------------------------

/// A means of constructing a 'struct'.
pub struct StructBuilder<'a, F: Fn(Member) -> Ident> {
    /// The 'struct' being constructed.
    target: &'a Struct,

    /// A map from field names to constructing variables.
    var_fn: F,
}

impl<F: Fn(Member) -> Ident> StructBuilder<'_, F> {
    /// The initializing variables for this 'struct'.
    pub fn init_vars(&self) -> impl Iterator<Item = Ident> + '_ {
        self.members().map(&self.var_fn)
    }

    /// The names of the sized fields of this 'struct'.
    pub fn sized_init_vars(&self) -> impl Iterator<Item = Ident> + '_ {
        self.sized_members().map(&self.var_fn)
    }

    /// The name of the last field of this 'struct'.
    pub fn unsized_init_var(&self) -> Option<Ident> {
        self.unsized_member().map(&self.var_fn)
    }
}

impl<F: Fn(Member) -> Ident> Deref for StructBuilder<'_, F> {
    type Target = Struct;

    fn deref(&self) -> &Self::Target {
        self.target
    }
}

impl<F: Fn(Member) -> Ident> ToTokens for StructBuilder<'_, F> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let ident = &self.ident;
        match self.fields {
            Fields::Named(_) => {
                let members = self.members();
                let init_vars = self.init_vars();
                quote! {
                    #ident { #(#members: #init_vars),* }
                }
            }

            Fields::Unnamed(_) => {
                let init_vars = self.init_vars();
                quote! {
                    #ident ( #(#init_vars),* )
                }
            }

            Fields::Unit => {
                quote! { #ident }
            }
        }
        .to_tokens(tokens);
    }
}
