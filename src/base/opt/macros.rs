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
        pub enum AllOptData<Octs> {
            $( $(
                $opt($module::$opt $( <$octets> )* ),
            )* )*
            Other(UnknownOptData<Octs>),
        }

        //--- From

        $( $(
            impl<Octs> From<$opt $( <$octets> )*> for AllOptData<Octs> {
                fn from(value: $module::$opt$( <$octets> )*) -> Self {
                    AllOptData::$opt(value)
                }
            }
        )* )*


        //--- Compose

        impl<Octs: AsRef<[u8]>> Compose for AllOptData<Octs> {
            fn compose<T: $crate::base::octets::OctetsBuilder + AsMut<[u8]>>(
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

        impl<Octs: AsRef<[u8]>> OptData for AllOptData<Octs> {
            fn code(&self) -> OptionCode {
                match *self {
                    $( $(
                        AllOptData::$opt(_) => OptionCode::$opt,
                    )* )*
                    AllOptData::Other(ref inner) => inner.code(),
                }
            }
        }

        impl<'a, Octs: Octets> ParseOptData<'a, Octs>
        for AllOptData<Octs::Range<'a>> {
            fn parse_option(
                code: OptionCode,
                parser: &mut Parser<'a, Octs>,
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
