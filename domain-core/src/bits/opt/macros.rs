//! Macros for option types.
//!
//! These macros are only used to generate enums in the parent module.
//! They are here in a separate module to keep the parent tidy.

macro_rules! opt_types {
    ( $(
        $module:ident::{
            $( $opt:ident ),*
        };
    )* ) => {

        $( $( pub use self::$module::$opt; )* )*

        $( pub mod $module; )*

        //------------ AllOptData --------------------------------------------

        #[derive(Clone, Debug)]
        pub enum AllOptData {
            $( $(
                $opt($module::$opt),
            )* )*
            Other(UnknownOptData),

            #[doc(hidden)]
            __Nonexhaustive(::void::Void),
        }

        //--- From

        $( $(
            impl From<$opt> for AllOptData {
                fn from(value: $module::$opt) -> Self {
                    AllOptData::$opt(value)
                }
            }
        )* )*

        
        //--- Compose

        impl Compose for AllOptData {
            fn compose_len(&self) -> usize {
                match self {
                    $( $(
                        &AllOptData::$opt(ref inner) => inner.compose_len(),
                    )* )*
                    &AllOptData::Other(ref inner) => inner.compose_len(),
                    &AllOptData::__Nonexhaustive(_) => unreachable!(),
                }
            }

            fn compose<B: ::bytes::BufMut>(&self, buf: &mut B) {
                match self {
                    $( $(
                        &AllOptData::$opt(ref inner) => inner.compose(buf),
                    )* )*
                    &AllOptData::Other(ref inner) => inner.compose(buf),
                    &AllOptData::__Nonexhaustive(_) => unreachable!()
                }
            }
        }


        //--- OptData

        impl OptData for AllOptData {
            type ParseErr = AllOptParseError;

            fn code(&self) -> OptionCode {
                match self {
                    $( $(
                        &AllOptData::$opt(_) => $opt::CODE,
                    )* )*
                    &AllOptData::Other(ref inner) => inner.code(),
                    &AllOptData::__Nonexhaustive(_) => unreachable!()
                }
            }

            fn parse_option(
                code: OptionCode,
                parser: &mut Parser,
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

        #[derive(Clone, Debug, Eq, Fail, PartialEq)]
        pub enum AllOptParseError {
            $( $(
                #[fail(display="{}", _0)]
                $opt(<$opt as OptData>::ParseErr),
            )* )*
            #[fail(display="short buffer")]
            ShortBuf,
        }

        impl From<::bits::parse::ShortBuf> for AllOptParseError {
            fn from(_: ::bits::parse::ShortBuf) -> Self {
                AllOptParseError::ShortBuf
            }
        }
    }
}
