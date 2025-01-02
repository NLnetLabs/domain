//! Helpers for generating `impl` blocks.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, ToTokens};
use syn::{punctuated::Punctuated, visit::Visit, *};

//----------- ImplSkeleton ---------------------------------------------------

/// The skeleton of an `impl` block.
pub struct ImplSkeleton {
    /// Lifetime parameters for the `impl` block.
    pub lifetimes: Vec<LifetimeParam>,

    /// Type parameters for the `impl` block.
    pub types: Vec<TypeParam>,

    /// Const generic parameters for the `impl` block.
    pub consts: Vec<ConstParam>,

    /// Whether the `impl` is unsafe.
    pub unsafety: Option<Token![unsafe]>,

    /// The trait being implemented.
    pub bound: Path,

    /// The type being implemented on.
    pub subject: Path,

    /// The where clause of the `impl` block.
    pub where_clause: WhereClause,

    /// The contents of the `impl`.
    pub contents: Block,

    /// A `const` block for asserting requirements.
    pub requirements: Block,
}

impl ImplSkeleton {
    /// Construct an [`ImplSkeleton`] for a [`DeriveInput`].
    pub fn new(input: &DeriveInput, unsafety: bool, bound: Path) -> Self {
        let mut lifetimes = Vec::new();
        let mut types = Vec::new();
        let mut consts = Vec::new();
        let mut subject_args = Punctuated::new();

        for param in &input.generics.params {
            match param {
                GenericParam::Lifetime(value) => {
                    lifetimes.push(value.clone());
                    let id = value.lifetime.clone();
                    subject_args.push(GenericArgument::Lifetime(id));
                }

                GenericParam::Type(value) => {
                    types.push(value.clone());
                    let id = value.ident.clone();
                    let id = TypePath {
                        qself: None,
                        path: Path {
                            leading_colon: None,
                            segments: [PathSegment {
                                ident: id,
                                arguments: PathArguments::None,
                            }]
                            .into_iter()
                            .collect(),
                        },
                    };
                    subject_args.push(GenericArgument::Type(id.into()));
                }

                GenericParam::Const(value) => {
                    consts.push(value.clone());
                    let id = value.ident.clone();
                    let id = TypePath {
                        qself: None,
                        path: Path {
                            leading_colon: None,
                            segments: [PathSegment {
                                ident: id,
                                arguments: PathArguments::None,
                            }]
                            .into_iter()
                            .collect(),
                        },
                    };
                    subject_args.push(GenericArgument::Type(id.into()));
                }
            }
        }

        let unsafety = unsafety.then_some(<Token![unsafe]>::default());

        let subject = Path {
            leading_colon: None,
            segments: [PathSegment {
                ident: input.ident.clone(),
                arguments: PathArguments::AngleBracketed(
                    AngleBracketedGenericArguments {
                        colon2_token: None,
                        lt_token: Default::default(),
                        args: subject_args,
                        gt_token: Default::default(),
                    },
                ),
            }]
            .into_iter()
            .collect(),
        };

        let where_clause =
            input.generics.where_clause.clone().unwrap_or(WhereClause {
                where_token: Default::default(),
                predicates: Punctuated::new(),
            });

        let contents = Block {
            brace_token: Default::default(),
            stmts: Vec::new(),
        };

        let requirements = Block {
            brace_token: Default::default(),
            stmts: Vec::new(),
        };

        Self {
            lifetimes,
            types,
            consts,
            unsafety,
            bound,
            subject,
            where_clause,
            contents,
            requirements,
        }
    }

    /// Require a bound for a type.
    ///
    /// If the type is concrete, a verifying statement is added for it.
    /// Otherwise, it is added to the where clause.
    pub fn require_bound(&mut self, target: Type, bound: TypeParamBound) {
        let mut visitor = ConcretenessVisitor {
            skeleton: self,
            is_concrete: true,
        };

        // Concreteness applies to both the type and the bound.
        visitor.visit_type(&target);
        visitor.visit_type_param_bound(&bound);

        if visitor.is_concrete {
            // Add a concrete requirement for this bound.
            self.requirements.stmts.push(parse_quote! {
                const _: fn() = || {
                    fn assert_impl<T: ?Sized + #bound>() {}
                    assert_impl::<#target>();
                };
            });
        } else {
            // Add this bound to the `where` clause.
            let mut bounds = Punctuated::new();
            bounds.push(bound);
            let pred = WherePredicate::Type(PredicateType {
                lifetimes: None,
                bounded_ty: target,
                colon_token: Default::default(),
                bounds,
            });
            self.where_clause.predicates.push(pred);
        }
    }

    /// Generate a unique lifetime with the given prefix.
    pub fn new_lifetime(&self, prefix: &str) -> Lifetime {
        [format_ident!("{}", prefix)]
            .into_iter()
            .chain((0u32..).map(|i| format_ident!("{}_{}", prefix, i)))
            .find(|id| self.lifetimes.iter().all(|l| l.lifetime.ident != *id))
            .map(|ident| Lifetime {
                apostrophe: Span::call_site(),
                ident,
            })
            .unwrap()
    }
}

impl ToTokens for ImplSkeleton {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            lifetimes,
            types,
            consts,
            unsafety,
            bound,
            subject,
            where_clause,
            contents,
            requirements,
        } = self;

        quote! {
            #unsafety
            impl<#(#lifetimes,)* #(#types,)* #(#consts,)*>
            #bound for #subject
            #where_clause
            #contents
        }
        .to_tokens(tokens);

        if !requirements.stmts.is_empty() {
            quote! {
                const _: () = #requirements;
            }
            .to_tokens(tokens);
        }
    }
}

//----------- ConcretenessVisitor --------------------------------------------

struct ConcretenessVisitor<'a> {
    /// The `impl` skeleton being added to.
    skeleton: &'a ImplSkeleton,

    /// Whether the visited type is concrete.
    is_concrete: bool,
}

impl<'ast> Visit<'ast> for ConcretenessVisitor<'_> {
    fn visit_lifetime(&mut self, i: &'ast Lifetime) {
        self.is_concrete = self.is_concrete
            && self.skeleton.lifetimes.iter().all(|l| l.lifetime != *i);
    }

    fn visit_ident(&mut self, i: &'ast Ident) {
        self.is_concrete = self.is_concrete
            && self.skeleton.types.iter().all(|t| t.ident != *i);
        self.is_concrete = self.is_concrete
            && self.skeleton.consts.iter().all(|c| c.ident != *i);
    }
}
