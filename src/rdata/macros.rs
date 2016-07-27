//! Macros for use in rdata definitions.

macro_rules! master_types {
    ( $( $module:ident::{  $( $rtype:ident ),*  };)* ) => {
        $(
            pub use self::$module::{ $( $rtype ),* };
        )*

        pub fn scan<S>(rtype: ::iana::RRType, scanner: &mut S,
                       origin: Option<&::bits::name::DNameSlice>)
                           -> ::master::ScanResult<Vec<u8>>
                    where S: ::master::Scanner {
            use ::rdata::generic;

            // First try the generic format for everything.
            let err = match generic::scan(scanner) {
                Ok(some) => return Ok(some),
                Err(err) => err 
            };
            // Now see if we have a master type that can parse this for real.
            match rtype {
                $(
                    $(
                        ::iana::RRType::$rtype => {
                            let mut res = Vec::new();
                            try!($rtype::scan_into(scanner, origin, &mut res));
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
