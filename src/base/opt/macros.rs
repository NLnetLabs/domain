//! Macros for option types.
//!
//! These macros are only used to generate enums in the parent module.
//! They are here in a separate module to keep the parent tidy.

macro_rules! opt_types {
    ( $(
        $module:ident::{
            $( $opt:ident $( < $( $octets:ident ),* > )? ),*
        };
    )* ) => {

        $( $( pub use self::$module::$opt; )* )*

        $( pub mod $module; )*

        //------------ AllOptData --------------------------------------------

        #[derive(Clone)]
        #[non_exhaustive]
        pub enum AllOptData<Octs, Name> {
            $( $(
                $opt($module::$opt $( < $( $octets ),* > )? ),
            )* )*
            Other(UnknownOptData<Octs>),
        }

        //--- OctetsFrom

        impl<Octs, Name, SrcOcts, SrcName>
        OctetsFrom<AllOptData<SrcOcts, SrcName>>
        for AllOptData<Octs, Name>
        where
            Octs: OctetsFrom<SrcOcts>,
            Name: OctetsFrom<SrcName, Error = Octs::Error>,
        {
            type Error = Octs::Error;

            fn try_octets_from(
                source: AllOptData<SrcOcts, SrcName>,
            ) -> Result<Self, Self::Error> {
                match source {
                    $( $(
                        AllOptData::$opt(opt) => {
                            Ok(AllOptData::$opt(
                                $module::$opt::try_octets_from(opt)?
                            ))
                        },
                    )* )*
                    AllOptData::Other(opt) => {
                        Ok(AllOptData::Other(
                            UnknownOptData::try_octets_from(opt)?
                        ))
                    }
                }
            }
        }

        //--- From

        $( $(
            impl<Octs, Name> From<$opt $( < $( $octets> ),* )?>
            for AllOptData<Octs, Name> {
                fn from(
                    value: $module::$opt$( < $( $octets ),* > )*
                ) -> Self {
                    AllOptData::$opt(value)
                }
            }
        )* )*

        //--- OptData

        impl<Octs, Name> OptData for AllOptData<Octs, Name> {
            fn code(&self) -> OptionCode {
                match *self {
                    $( $(
                        AllOptData::$opt(_) => $module::$opt::CODE,
                    )* )*
                    AllOptData::Other(ref inner) => inner.code(),
                }
            }
        }

        impl<'a, Octs: Octets> ParseOptData<'a, Octs>
        for AllOptData<Octs::Range<'a>, Name<Octs::Range<'a>>> {
            fn parse_option(
                code: OptionCode,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                match code {
                    $( $(
                        $module::$opt::CODE => {
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

        impl<Octs, Name> ComposeOptData for AllOptData<Octs, Name>
        where Octs: AsRef<[u8]>, Name: ToName {
            fn compose_len(&self) -> u16 {
                match *self {
                    $( $(
                        AllOptData::$opt(ref inner) => inner.compose_len(),
                    )* )*
                    AllOptData::Other(ref inner) => inner.compose_len(),
                }
            }

            fn compose_option<Target: octseq::builder::OctetsBuilder + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                match *self {
                    $( $(
                        AllOptData::$opt(ref inner) => {
                            inner.compose_option(target)
                        }
                    )* )*
                    AllOptData::Other(ref inner) => {
                        inner.compose_option(target)
                    }
                }
            }
        }

        //--- Debug

        impl<Octs, Name> fmt::Debug for AllOptData<Octs, Name>
        where Octs: AsRef<[u8]>, Name: fmt::Display {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match *self {
                    $( $(
                        AllOptData::$opt(ref inner) => {
                            fmt::Debug::fmt(inner, f)
                        }
                    )* )*
                    AllOptData::Other(ref inner) => {
                            fmt::Debug::fmt(inner, f)
                    }
                }
            }
        }
    }
}
