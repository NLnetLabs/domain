//! Macros for use in rdata definitions.

macro_rules! master_types {
    ( $( $module:ident::{  $( $rtype:ident => $full_rtype:ty, )*  })* ) => {
        $(
            pub use self::$module::{ $( $rtype ),* };
        )*

        #[derive(Clone, Debug)]
        pub enum MasterRecordData {
            $(
                $(
                    $rtype($full_rtype),
                )*
            )*
            Generic(::iana::Rtype, Vec<u8>),
        }

        impl MasterRecordData {
            pub fn scan<S>(rtype: ::iana::Rtype, scanner: &mut S,
                           origin: Option<&::bits::name::DNameSlice>)
                           -> ::master::ScanResult<Self>
                        where S: ::master::Scanner {
                // First try the generic format for everything.
                let err = match ::rdata::generic::scan(scanner) {
                    Ok(some) => {
                        return Ok(MasterRecordData::Generic(rtype, some))
                    }
                    Err(err) => err
                };
                // Now see if we have a master type that can parse this for
                // real.
                match rtype {
                    $(
                        $(
                            ::iana::Rtype::$rtype => {
                                $rtype::scan(scanner, origin)
                                    .map(MasterRecordData::$rtype)
                            }
                        )*
                    )*
                    // We don’t. Good thing we kept the error.
                    _ => Err(err)
                }
            }
        }

        impl ::bits::RecordData for MasterRecordData {
            fn rtype(&self) -> ::iana::Rtype {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref data) => {
                                data.rtype()
                            }
                        )*
                    )*
                    MasterRecordData::Generic(rtype, _) => rtype
                }
            }

            fn compose<C>(&self, mut target: C) -> ::bits::ComposeResult<()>
                       where C: AsMut<::bits::Composer> {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref data) => {
                                data.compose(target)
                            }
                        )*
                    )*
                    MasterRecordData::Generic(_, ref data) => {
                        target.as_mut().compose_bytes(data)
                    }
                }
            }
        }

        impl ::std::fmt::Display for MasterRecordData {
            fn fmt(&self, f: &mut ::std::fmt::Formatter)
                   -> ::std::fmt::Result {
                match *self {
                    $(
                        $(
                            MasterRecordData::$rtype(ref data) => {
                                ::std::fmt::Display::fmt(data, f)
                            }
                        )*
                    )*
                    MasterRecordData::Generic(_, ref data) => {
                        ::rdata::generic::fmt(data, f)
                    }
                }
            }
        }

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
    }
}

macro_rules! pseudo_types {
    ( $( $module:ident::{  $( $rtype:ident ),*  };)* ) => {
        $(
            pub use self::$module::{ $( $rtype ),* };
        )*
    }
}
