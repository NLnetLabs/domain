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
        #[non_exhaustive]
        pub enum AllOptData<Octets> {
            $( $(
                $opt($module::$opt $( <$octets> )* ),
            )* )*
            Other(UnknownOptData<Octets>),
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
            fn compose<T: $crate::base::octets::OctetsBuilder>(
                &self, target: &mut T
            ) -> Result<(), ShortBuf> {
                match *self {
                    $( $(
                        AllOptData::$opt(ref inner) => inner.compose(target),
                    )* )*
                    AllOptData::Other(ref inner) => inner.compose(target),
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
                }
            }
        }

        impl<Ref: OctetsRef> ParseOptData<Ref> for AllOptData<Ref::Range> {
            fn parse_option(
                code: OptionCode,
                parser: &mut Parser<Ref>,
            ) -> Result<Option<Self>, ParseError> {
                match code {
                    $( $(
                        OptionCode::$opt => {
                            Ok(Some(AllOptData::$opt(
                                $opt::parse(parser)?
                            )))
                        }
                    )* )*
                    _ => {
                        Ok(UnknownOptData::parse_option(
                            code, parser
                        )?.map(AllOptData::Other))
                    }
                }
            }
        }
    }
}
