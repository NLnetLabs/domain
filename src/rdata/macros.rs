//! Macros for use in rdata definitions.
//!
//! These macros are not public but are used by the super module only. They
//! are here so that `mod.rs` doesn’t become too unwieldly.

macro_rules! master_types {
    ( $( $module:ident::{  $( $rtype:ident => $full_rtype:ty, )*  })* ) => {
        $(
            pub use self::$module::{ $( $rtype ),* };
        )*

        /// An enum with all the record data that can appear in master files.
        ///
        /// This enum contains variants for all the implemented record data
        /// types in their owned form plus the `Generic` variant record data
        /// of any other type.
        #[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
        pub enum MasterRecordData {
            $(
                $(
                    $rtype($full_rtype),
                )*
            )*
            Other(::bits::rdata::UnknownRecordData),
        }

        //--- From

        $(
            $(
                impl From<$full_rtype> for MasterRecordData {
                    fn from(value: $full_rtype) -> Self {
                        MasterRecordData::$rtype(value)
                    }
                }
            )*
        )*


        //--- Compose and Compress

        impl ::bits::compose::Compose for MasterRecordData {
            fn compose_len(&self) -> usize {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref inner) => {
                                inner.compose_len()
                            }
                        )*
                    )*
                    MasterRecordData::Other(ref inner) => inner.compose_len()
                }
            }

            fn compose<B: ::bytes::BufMut>(&self, buf: &mut B) {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref inner) => {
                                inner.compose(buf)
                            }
                        )*
                    )*
                    MasterRecordData::Other(ref inner) => inner.compose(buf)
                }
            }
        }

        impl ::bits::compose::Compress for MasterRecordData {
            fn compress(&self, buf: &mut ::bits::compose::Compressor)
                        -> Result<(), ::bits::parse::ShortBuf> {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref inner) => {
                                inner.compress(buf)
                            }
                        )*
                    )*
                    MasterRecordData::Other(ref inner) => inner.compress(buf)
                }
            }
        }

        //--- RecordData

        impl ::bits::rdata::RecordData for MasterRecordData {
            fn rtype(&self) -> ::iana::Rtype {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref inner) => {
                                inner.rtype()
                            }
                        )*
                    )*
                    MasterRecordData::Other(ref inner) => inner.rtype()
                }
            }
        }

        //--- (Scan) and Print

        impl MasterRecordData {
            pub fn scan<C>(rtype: ::iana::Rtype,
                           scanner: &mut ::master::scan::Scanner<C>)
                           -> Result<Self, ::master::scan::ScanError>
                        where C: ::master::scan::CharSource {
                use ::master::scan::Scan;

                match rtype {
                    $(
                        $(
                            ::iana::Rtype::$rtype => {
                                $rtype::scan(scanner)
                                       .map(MasterRecordData::$rtype)
                            }
                        )*
                    )*
                    _ => {
                        ::bits::rdata::UnknownRecordData::scan(rtype, scanner)
                            .map(MasterRecordData::Other)
                    }
                }
            }
        }

        impl ::master::print::Print for MasterRecordData {
            fn print<W>(&self, printer: &mut ::master::print::Printer<W>)
                        -> Result<(), ::std::io::Error>
                     where W: ::std::io::Write {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref inner) => {
                                inner.print(printer)
                            }
                        )*
                    )*
                    MasterRecordData::Other(ref inner) => inner.print(printer)
                }
            }
        }

        
        //--- Display

        impl ::std::fmt::Display for MasterRecordData {
            fn fmt(&self, f: &mut ::std::fmt::Formatter)
                   -> ::std::fmt::Result {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref inner) => {
                                inner.fmt(f)
                            }
                        )*
                    )*
                    MasterRecordData::Other(ref inner) => inner.fmt(f)
                }
            }
        }


        /*
        /// Helper function for `fmt_rdata()`.
        ///
        /// This function contains the part of `fmt_rdata()` that needs to
        /// be generated via the `master_types!` macro.
        fn fmt_master_data(rtype: ::iana::Rtype,
                           parser: &mut ::bits::Parser,
                           f: &mut ::std::fmt::Formatter)
                           -> Result<Option<()>, ::std::fmt::Error> {
            use bits::rdata::ParsedRecordData;

            match rtype {
                $(
                    $(
                        ::iana::Rtype::$rtype => {
                            match ::rdata::parsed::$rtype::parse(rtype,
                                                                 parser) {
                                Ok(None) => unreachable!(),
                                Ok(Some(data)) => {
                                    ::std::fmt::Display::fmt(&data, f)
                                                        .map(Some)
                                }
                                Err(err) => {
                                    write!(f, "<invalid data: {}>", err)
                                        .map(Some)
                                }
                            }
                        }
                    )*
                )*
                _ => Ok(None)
            }
        }
        */
    }
}

macro_rules! pseudo_types {
    ( $( $module:ident::{  $( $rtype:ident ),*  };)* ) => {
        $(
            pub use self::$module::{ $( $rtype ),* };
        )*
    }
}
