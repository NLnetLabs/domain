//! Macros for use in rdata definitions.

macro_rules! master_types {
    ( $( $module:ident::{  $( $rtype:ident ),*  };)* ) => {
        $(
            pub use self::$module::{ $( $rtype ),* };
        )*

        pub fn scan<'a, R>(rtype: ::iana::RRType,
                           stream: &mut ::master::Stream<R>,
                           origin: Option<&'a ::bits::name::DNameSlice>)
                           -> ::master::Result<Vec<u8>>
                    where R: ::std::io::Read {
            use ::bits::rdata::GenericRecordData;

            // First try the generic format for everything.
            let err = match GenericRecordData::scan(stream) {
                Ok(some) => return Ok(some),
                Err(err) => err 
            };
            // Now see if we have a master type that can parse this for real.
            match rtype {
                $(
                    $(
                        ::iana::RRType::$rtype => {
                            let mut res = Vec::new();
                            try!($rtype::scan_into(stream, origin, &mut res));
                            Ok(res)
                        }
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
