//! Macros for option types.
//!
//! These macros are only used to generate enums in the parent module.
//! They are here in a separate module to keep the parent tidy.

macro_rules! opt_types {
    ( $(
        $module:ident::{
            $( $opt:ident $( <$octets:ident> )* ),*
        };
    )* ) => {

        $( $( pub use self::$module::$opt; )* )*

        $( pub mod $module; )*

        //------------ AllOptData --------------------------------------------

        // TODO Impl Debug.
        #[derive(Clone)]
        pub enum AllOptData<Octets> {
            $( $(
                $opt($module::$opt $( <$octets> )* ),
            )* )*
            Other(UnknownOptData<Octets>),

            #[doc(hidden)]
            __Nonexhaustive(::void::Void),
        }

        //--- From

        $( $(
            impl<Octets> From<$opt $( <$octets> )*> for AllOptData<Octets> {
                fn from(value: $module::$opt$( <$octets> )*) -> Self {
                    AllOptData::$opt(value)
                }
            }
        )* )*

        
        //--- Compose

        impl<Octets: AsRef<[u8]>> Compose for AllOptData<Octets> {
            fn compose<T: $crate::octets::OctetsBuilder>(
                &self, target: &mut T
            ) -> Result<(), ShortBuf> {
                match *self {
                    $( $(
                        AllOptData::$opt(ref inner) => inner.compose(target),
                    )* )*
                    AllOptData::Other(ref inner) => inner.compose(target),
                    AllOptData::__Nonexhaustive(_) => unreachable!()
                }
            }
        }


        //--- OptData

        impl<Octets: AsRef<[u8]>> OptData for AllOptData<Octets> {
            fn code(&self) -> OptionCode {
                match *self {
                    $( $(
                        AllOptData::$opt(_) => OptionCode::$opt,
                    )* )*
                    AllOptData::Other(ref inner) => inner.code(),
                    AllOptData::__Nonexhaustive(_) => unreachable!()
                }
            }
        }

        impl<Octets> ParseOptData<Octets> for AllOptData<Octets>
        where Octets: $crate::parse::ParseSource {
            type ParseErr = AllOptParseError<Octets>;

            fn parse_option(
                code: OptionCode,
                parser: &mut Parser<Octets>,
                len: usize
            ) -> Result<Option<Self>, Self::ParseErr> {
                match code {
                    $( $(
                        OptionCode::$opt => {
                            Ok(Some(AllOptData::$opt(
                                $opt::parse_all(parser, len)
                                    .map_err(AllOptParseError::$opt)?
                            )))
                        }
                    )* )*
                    _ => {
                        Ok(UnknownOptData::parse_option(
                            code, parser, len
                        )?.map(AllOptData::Other))
                    }
                }
            }
        }


        //------------ AllOptParseError --------------------------------------

        #[derive(Clone, Eq, PartialEq)]
        pub enum AllOptParseError<Octets: $crate::parse::ParseSource> {
            $( $(
                $opt(<$opt $( <$octets> )* as ParseOptData<Octets>>::ParseErr),
            )* )*
            ShortBuf,
        }

        #[cfg(feature = "std")]
        impl<Octets> std::error::Error for AllOptParseError<Octets> 
        where Octets: $crate::parse::ParseSource { }

        impl<Octets> core::fmt::Debug for AllOptParseError<Octets>
        where Octets: $crate::parse::ParseSource {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "AllOptParseError::")?;
                match *self {
                    $( $(
                        AllOptParseError::$opt(ref inner) => {
                            write!(
                                f,
                                concat!(stringify!($opt), "({:?})"),
                                inner
                            )
                        }
                    )* )*
                    AllOptParseError::ShortBuf => {
                        "ShortBuf".fmt(f)
                    }
                }
            }
        }

        impl<Octets> core::fmt::Display for AllOptParseError<Octets>
        where Octets: $crate::parse::ParseSource {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                match *self {
                    $( $(
                        AllOptParseError::$opt(ref inner) => inner.fmt(f),
                    )* )*
                    AllOptParseError::ShortBuf => {
                        "short buffer".fmt(f)
                    }
                }
            }
        }

        impl<Octets> From<$crate::parse::ShortBuf> for
                                                    AllOptParseError<Octets>
        where Octets: $crate::parse::ParseSource {
            fn from(_: $crate::parse::ShortBuf) -> Self {
                AllOptParseError::ShortBuf
            }
        }
    }
}
