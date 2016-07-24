//! Macros for use in rdata definitions.

macro_rules! master_types {
    ( $( $module:ident::{  $( $rtype:ident ),*  };)* ) => {
        $(
            pub use self::$module::{ $( $rtype ),* };
        )*

        pub fn scan_into<R, B>(rtype: ::iana::RRType,
                               stream: &mut ::master::Stream<R>,
                               origin: &::bits::name::DNameSlice,
                               target: &mut B)
                               -> ::master::Result<()>
                         where R: ::std::io::Read,
                               B: ::bits::bytes::PushBytes {
            use ::bits::rdata::GenericRecordData;

            // First try the generic format for everything.
            let err = match GenericRecordData::scan_into(stream, target) {
                Ok(()) => return Ok(()),
                Err(err) => err 
            };
            // Now see if we have a master type that can parse this for real.
            match rtype {
                $(
                    $(
                        ::iana::RRType::$rtype =>
                                   $rtype::scan_into(stream, origin, target),
                    )*
                )*
                // We don’t. Good thing we kept the error.
                _ => Err(err)
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
