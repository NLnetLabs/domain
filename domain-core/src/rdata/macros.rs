//! Macros for use in rdata definitions.
//!
//! These macros are not public but are used by the super module only. They
//! are here so that `mod.rs` doesn’t become too unwieldly.

macro_rules! rdata_types {
    ( $(
        $module:ident::{
            $(
                master {
                    $( $mtype:ident $( <$mn:ident> )*, )*
                }
            )*
            $(
                pseudo {
                    $( $ptype:ident $( <$pn:ident> )*, )*
                }
            )*

        }
    )* ) => {
        $(
            pub use self::$module::{
                $( $( $mtype, )* )*
                $( $( $ptype ),* )*
            };
        )*


        //------------- MasterRecordData -------------------------------------

        #[derive(Clone, Debug)]
        pub enum MasterRecordData<N> {
            $( $( $(
                $mtype($mtype $( <$mn> )*),
            )* )* )*
            Other($crate::rdata::UnknownRecordData),

            #[doc(hidden)]
            __Nonexhaustive(::void::Void),
        }


        //--- From

        $( $( $(
            impl<N> From<$mtype $( < $mn >)*> for MasterRecordData<N> {
                fn from(value: $mtype $( < $mn >)*) -> Self {
                    MasterRecordData::$mtype(value)
                }
            }
        )* )* )*

        impl<N> From<$crate::rdata::UnknownRecordData>
                    for MasterRecordData<N> {
            fn from(value: $crate::rdata::UnknownRecordData) -> Self {
                MasterRecordData::Other(value)
            }
        }


        //--- PartialEq and Eq

        impl<N> PartialEq for MasterRecordData<N>
        where N: PartialEq {
            fn eq(&self, other: &Self) -> bool {
                match (self, other) {
                    $( $( $(
                        (
                            &MasterRecordData::$mtype(ref self_inner),
                            &MasterRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.eq(other_inner)
                        }
                    )* )* )*
                    (_, &MasterRecordData::__Nonexhaustive(_))
                        => unreachable!(),
                    (&MasterRecordData::__Nonexhaustive(_), _)
                        => unreachable!(),
                    _ => false
                }
            }
        }

        impl<N> Eq for MasterRecordData<N>
        where N: PartialEq { }


        //--- Hash
 
        impl<N> ::std::hash::Hash for MasterRecordData<N>
        where N: ::std::hash::Hash {
            fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            $crate::iana::Rtype::$mtype.hash(state);
                            inner.hash(state)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => {
                        inner.rtype().hash(state);
                        inner.data().hash(state);
                    }
                    MasterRecordData::__Nonexhaustive(_) => unreachable!()
                }
            }
        }


        //--- Compose and Compress
        //
        //    No Parse or ParseAll because Other variant needs to know the
        //    record type.

        impl<N> $crate::compose::Compose for MasterRecordData<N>
        where N: $crate::compose::Compose
        {
            fn compose_len(&self) -> usize {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compose_len()
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.compose_len(),
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }

            fn compose<B: ::bytes::BufMut>(&self, buf: &mut B) {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compose(buf)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.compose(buf),
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }

        impl<N> $crate::compose::Compress for MasterRecordData<N>
        where N: $crate::compose::Compress + $crate::compose::Compose {
            fn compress(&self, buf: &mut $crate::compose::Compressor)
                        -> Result<(), $crate::parse::ShortBuf> {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compress(buf)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.compress(buf),
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }


        //--- RecordData and ParseRecordData

        impl<N> $crate::rdata::RecordData for MasterRecordData<N>
        where N: $crate::compose::Compose + $crate::compose::Compress
        {
            fn rtype(&self) -> $crate::iana::Rtype {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.rtype()
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.rtype(),
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }

        impl $crate::rdata::ParseRecordData
            for MasterRecordData<$crate::name::ParsedDname>
        {
            type Err = MasterDataParseError;

            fn parse_data(rtype: $crate::iana::Rtype,
                          parser: &mut $crate::parse::Parser, rdlen: usize)
                          -> Result<Option<Self>, Self::Err> {
                use $crate::parse::ParseAll;

                match rtype {
                    $( $( $(
                        $crate::iana::Rtype::$mtype => {
                            Ok(Some(MasterRecordData::$mtype(
                                $mtype::parse_all(parser, rdlen)
                                    .map_err(MasterDataParseError::$mtype)?
                            )))
                        }
                    )* )* )*
                    _ => {
                        Ok($crate::rdata::UnknownRecordData::parse_data(
                            rtype, parser, rdlen
                        )?.map(MasterRecordData::Other))
                    }
                }
            }
        }


        //--- (Scan) and Display

        impl<N: $crate::master::scan::Scan> MasterRecordData<N> {
            pub fn scan<C>(rtype: $crate::iana::Rtype,
                           scanner: &mut $crate::master::scan::Scanner<C>)
                           -> Result<Self, $crate::master::scan::ScanError>
                        where C: $crate::master::scan::CharSource {
                use $crate::master::scan::Scan;

                match rtype {
                    $( $( $(
                        $crate::iana::Rtype::$mtype => {
                            $mtype::scan(scanner)
                                   .map(MasterRecordData::$mtype)
                        }
                    )* )* )*
                    _ => {
                        $crate::rdata::UnknownRecordData::scan(rtype, scanner)
                            .map(MasterRecordData::Other)
                    }
                }
            }
        }

        impl<N> ::std::fmt::Display for MasterRecordData<N>
        where N: ::std::fmt::Display {
            fn fmt(&self, f: &mut ::std::fmt::Formatter)
                   -> ::std::fmt::Result {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.fmt(f)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.fmt(f),
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }


        //------------- AllRecordData ----------------------------------------

        #[derive(Clone, Debug)]
        pub enum AllRecordData<N> {
            $( $( $(
                $mtype($mtype $( <$mn> )*),
            )* )* )*
            $( $( $(
                $ptype($ptype $( <$pn> )*),
            )* )* )*
            Opt($crate::opt::Opt),
            Other($crate::rdata::UnknownRecordData),

            #[doc(hidden)]
            __Nonexhaustive(::void::Void),
        }

        //--- From and Into

        $( $( $(
            impl<N> From<$mtype $( < $mn >)*> for AllRecordData<N> {
                fn from(value: $mtype $( < $mn >)*) -> Self {
                    AllRecordData::$mtype(value)
                }
            }
        )* )* )*

        $( $( $(
            impl<N> From<$ptype $( < $pn >)*> for AllRecordData<N> {
                fn from(value: $ptype $( < $pn >)*) -> Self {
                    AllRecordData::$ptype(value)
                }
            }
        )* )* )*

        impl<N> From<$crate::opt::Opt> for AllRecordData<N> {
            fn from(value: $crate::opt::Opt) -> Self {
                AllRecordData::Opt(value)
            }
        }

        impl<N> From<$crate::rdata::UnknownRecordData> for AllRecordData<N> {
            fn from(value: $crate::rdata::UnknownRecordData) -> Self {
                AllRecordData::Other(value)
            }
        }

        impl<N> Into<Result<MasterRecordData<N>, Self>> for AllRecordData<N>
        {
            fn into(self) -> Result<MasterRecordData<N>, Self> {
                match self {
                    $( $( $(
                        AllRecordData::$mtype(inner) => {
                            Ok(MasterRecordData::$mtype(inner))
                        }
                    )* )* )*
                    AllRecordData::Other(inner) => {
                        Ok(MasterRecordData::Other(inner))
                    }
                    _ => Err(self)
                }
            }
        }


        //--- PartialEq and Eq

        impl<N> PartialEq for AllRecordData<N>
        where N: PartialEq {
            fn eq(&self, other: &Self) -> bool {
                match (self, other) {
                    $( $( $(
                        (
                            &AllRecordData::$mtype(ref left),
                            &AllRecordData::$mtype(ref right)
                        ) => {
                            left.eq(right)
                        }
                    )* )* )*
                    $( $( $(
                        (
                            &AllRecordData::$ptype(ref left),
                            &AllRecordData::$ptype(ref right)
                        ) => {
                            left.eq(right)
                        }
                    )* )* )*
                    (_, &AllRecordData::__Nonexhaustive(_))
                        => unreachable!(),
                    (&AllRecordData::__Nonexhaustive(_), _)
                        => unreachable!(),
                    (_, _) => false
                }
            }
        }

        impl<N> Eq for AllRecordData<N>
        where N: PartialEq { }


        //--- Hash

        impl<N> ::std::hash::Hash for AllRecordData<N>
        where N: ::std::hash::Hash {
            fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
                use $crate::rdata::RecordData;
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            $crate::iana::Rtype::$mtype.hash(state);
                            inner.hash(state)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            $crate::iana::Rtype::$ptype.hash(state);
                            inner.hash(state)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => {
                        inner.rtype().hash(state);
                        inner.hash(state);
                    }
                    AllRecordData::Other(ref inner) => {
                        inner.rtype().hash(state);
                        inner.data().hash(state);
                    }
                    AllRecordData::__Nonexhaustive(_) => unreachable!()
                }
            }
        }


        //--- Compose and Compress
        //
        //    No Parse or ParseAll because Other variant needs to know the
        //    record type.
        impl<N> $crate::compose::Compose for AllRecordData<N>
        where N: $crate::compose::Compose
        {
            fn compose_len(&self) -> usize {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.compose_len()
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.compose_len()
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => inner.compose_len(),
                    AllRecordData::Other(ref inner) => inner.compose_len(),
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }

            fn compose<B: ::bytes::BufMut>(&self, buf: &mut B) {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.compose(buf)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.compose(buf)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => inner.compose(buf),
                    AllRecordData::Other(ref inner) => inner.compose(buf),
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }

        impl<N> $crate::compose::Compress for AllRecordData<N>
        where N: $crate::compose::Compress + $crate::compose::Compose {
            fn compress(&self, buf: &mut $crate::compose::Compressor)
                        -> Result<(), $crate::parse::ShortBuf> {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.compress(buf)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.compress(buf)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => inner.compress(buf),
                    AllRecordData::Other(ref inner) => inner.compress(buf),
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }


        //--- RecordData and ParseRecordData

        impl<N> $crate::rdata::RecordData for AllRecordData<N>
        where N: $crate::compose::Compose + $crate::compose::Compress
        {
            fn rtype(&self) -> $crate::iana::Rtype {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.rtype()
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.rtype()
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => inner.rtype(),
                    AllRecordData::Other(ref inner) => inner.rtype(),
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }

        impl $crate::rdata::ParseRecordData
            for AllRecordData<$crate::name::ParsedDname>
        {
            type Err = AllDataParseError;

            fn parse_data(rtype: $crate::iana::Rtype,
                          parser: &mut $crate::parse::Parser, rdlen: usize)
                          -> Result<Option<Self>, Self::Err> {
                use $crate::parse::ParseAll;

                match rtype {
                    $( $( $(
                        $crate::iana::Rtype::$mtype => {
                            Ok(Some(AllRecordData::$mtype(
                                $mtype::parse_all(parser, rdlen)
                                    .map_err(AllDataParseError::$mtype)?
                            )))
                        }
                    )* )* )*
                    $( $( $(
                        $crate::iana::Rtype::$ptype => {
                            Ok(Some(AllRecordData::$ptype(
                                $ptype::parse_all(parser, rdlen)
                                    .map_err(AllDataParseError::$ptype)?
                            )))
                        }
                    )* )* )*
                    $crate::iana::Rtype::Opt => {
                        Ok(Some(AllRecordData::Opt(
                            $crate::opt::Opt::parse_all(parser, rdlen)
                                .map_err(AllDataParseError::Opt)?
                        )))
                    }
                    _ => {
                        Ok($crate::rdata::UnknownRecordData::parse_data(
                            rtype, parser, rdlen
                        )?.map(AllRecordData::Other))
                    }
                }
            }
        }

        
        //--- Display

        impl<N> ::std::fmt::Display for AllRecordData<N>
        where N: ::std::fmt::Display {
            fn fmt(&self, f: &mut ::std::fmt::Formatter)
                   -> ::std::fmt::Result {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.fmt(f)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.fmt(f)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => inner.fmt(f),
                    AllRecordData::Other(ref inner) => inner.fmt(f),
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }


        //------------- MasterDataParseError ---------------------------------

        parse_err!(MasterDataParseError,
            $( $( $(
                { $mtype $( $mn $crate::name::ParsedDname )* }
            )* )* )*
        );


        //------------- AllDataParseError ------------------------------------

        parse_err!(AllDataParseError,
            $( $( $(
                { $mtype $( $mn $crate::name::ParsedDname )* }
            )* )* )*
            $( $( $(
                { $ptype $( $pn $crate::name::ParsedDname )* }
            )* )* )*
            { Opt  }
        );
    }
}


macro_rules! parse_err {
    ( $err:ident, $( { $t:ident $( $x:ident $gen:ty )* } )* ) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub enum $err {
            $(
                $t(<$t $( <$gen> )* as $crate::rdata::ParseRecordData>::Err),
            )*
            ShortBuf,
        }

        impl std::error::Error for $err { }

        impl std::fmt::Display for $err {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match *self {
                    $(
                        $err::$t(ref inner) => inner.fmt(f),
                    )*
                    $err::ShortBuf => {
                        "short buffer".fmt(f)
                    }
                }
            }
        }

        impl From<$crate::parse::ShortBuf> for $err {
            fn from(_: $crate::parse::ShortBuf) -> Self {
                $err::ShortBuf
            }
        }
    }
}

