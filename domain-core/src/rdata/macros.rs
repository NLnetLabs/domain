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

        #[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
        pub enum MasterRecordData<N> {
            $( $( $(
                $mtype($mtype $( <$mn> )*),
            )* )* )*
            Other(::bits::rdata::UnknownRecordData),
        }


        //--- From

        $( $( $(
            impl<N> From<$mtype $( < $mn >)*> for MasterRecordData<N> {
                fn from(value: $mtype $( < $mn >)*) -> Self {
                    MasterRecordData::$mtype(value)
                }
            }
        )* )* )*

        impl<N> From<::bits::rdata::UnknownRecordData> for MasterRecordData<N> {
            fn from(value: ::bits::rdata::UnknownRecordData) -> Self {
                MasterRecordData::Other(value)
            }
        }


        //--- Compose and Compress
        //
        //    No Parse or ParseAll because Other variant needs to know the
        //    record type.

        impl<N> ::bits::compose::Compose for MasterRecordData<N>
        where N: ::bits::compose::Compose
        {
            fn compose_len(&self) -> usize {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compose_len()
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.compose_len()
                }
            }

            fn compose<B: ::bytes::BufMut>(&self, buf: &mut B) {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compose(buf)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.compose(buf)
                }
            }
        }

        impl<N> ::bits::compose::Compress for MasterRecordData<N>
        where N: ::bits::compose::Compress {
            fn compress(&self, buf: &mut ::bits::compose::Compressor)
                        -> Result<(), ::bits::parse::ShortBuf> {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compress(buf)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.compress(buf)
                }
            }
        }


        //--- RecordData and ParseRecordData

        impl<N> ::bits::rdata::RecordData for MasterRecordData<N>
        where N: ::bits::compose::Compose + ::bits::compose::Compress
        {
            fn rtype(&self) -> ::iana::Rtype {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.rtype()
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.rtype()
                }
            }
        }

        impl ::bits::rdata::ParseRecordData
            for MasterRecordData<::bits::name::ParsedDname>
        {
            type Err = MasterDataParseError;

            fn parse_data(rtype: ::iana::Rtype,
                          parser: &mut ::bits::parse::Parser, rdlen: usize)
                          -> Result<Option<Self>, Self::Err> {
                use bits::parse::ParseAll;

                match rtype {
                    $( $( $(
                        ::iana::Rtype::$mtype => {
                            Ok(Some(MasterRecordData::$mtype(
                                $mtype::parse_all(parser, rdlen)
                                    .map_err(MasterDataParseError::$mtype)?
                            )))
                        }
                    )* )* )*
                    _ => {
                        Ok(::bits::rdata::UnknownRecordData::parse_data(
                            rtype, parser, rdlen
                        )?.map(MasterRecordData::Other))
                    }
                }
            }
        }


        //--- (Scan) and Display

        impl<N: ::master::scan::Scan> MasterRecordData<N> {
            pub fn scan<C>(rtype: ::iana::Rtype,
                           scanner: &mut ::master::scan::Scanner<C>)
                           -> Result<Self, ::master::scan::ScanError>
                        where C: ::master::scan::CharSource {
                use ::master::scan::Scan;

                match rtype {
                    $( $( $(
                        ::iana::Rtype::$mtype => {
                            $mtype::scan(scanner)
                                   .map(MasterRecordData::$mtype)
                        }
                    )* )* )*
                    _ => {
                        ::bits::rdata::UnknownRecordData::scan(rtype, scanner)
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
                    MasterRecordData::Other(ref inner) => inner.fmt(f)
                }
            }
        }


        //------------- AllRecordData ----------------------------------------

        #[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
        pub enum AllRecordData<N> {
            $( $( $(
                $mtype($mtype $( <$mn> )*),
            )* )* )*
            $( $( $(
                $ptype($ptype $( <$pn> )*),
            )* )* )*
            Other(::bits::rdata::UnknownRecordData),
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

        impl<N> From<::bits::rdata::UnknownRecordData> for AllRecordData<N> {
            fn from(value: ::bits::rdata::UnknownRecordData) -> Self {
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


        //--- Compose and Compress
        //
        //    No Parse or ParseAll because Other variant needs to know the
        //    record type.
        impl<N> ::bits::compose::Compose for AllRecordData<N>
        where N: ::bits::compose::Compose
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
                    AllRecordData::Other(ref inner) => inner.compose_len()
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
                    AllRecordData::Other(ref inner) => inner.compose(buf)
                }
            }
        }

        impl<N> ::bits::compose::Compress for AllRecordData<N>
        where N: ::bits::compose::Compress {
            fn compress(&self, buf: &mut ::bits::compose::Compressor)
                        -> Result<(), ::bits::parse::ShortBuf> {
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
                    AllRecordData::Other(ref inner) => inner.compress(buf)
                }
            }
        }


        //--- RecordData and ParseRecordData

        impl<N> ::bits::rdata::RecordData for AllRecordData<N>
        where N: ::bits::compose::Compose + ::bits::compose::Compress
        {
            fn rtype(&self) -> ::iana::Rtype {
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
                    AllRecordData::Other(ref inner) => inner.rtype()
                }
            }
        }

        impl ::bits::rdata::ParseRecordData
            for AllRecordData<::bits::name::ParsedDname>
        {
            type Err = AllDataParseError;

            fn parse_data(rtype: ::iana::Rtype,
                          parser: &mut ::bits::parse::Parser, rdlen: usize)
                          -> Result<Option<Self>, Self::Err> {
                use bits::parse::ParseAll;

                match rtype {
                    $( $( $(
                        ::iana::Rtype::$mtype => {
                            Ok(Some(AllRecordData::$mtype(
                                $mtype::parse_all(parser, rdlen)
                                    .map_err(AllDataParseError::$mtype)?
                            )))
                        }
                    )* )* )*
                    $( $( $(
                        ::iana::Rtype::$ptype => {
                            Ok(Some(AllRecordData::$ptype(
                                $ptype::parse_all(parser, rdlen)
                                    .map_err(AllDataParseError::$ptype)?
                            )))
                        }
                    )* )* )*
                    _ => {
                        Ok(::bits::rdata::UnknownRecordData::parse_data(
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
                    AllRecordData::Other(ref inner) => inner.fmt(f)
                }
            }
        }


        //------------- MasterDataParseError ---------------------------------

        parse_err!(MasterDataParseError,
            $( $( $(
                { $mtype $( $mn ::bits::name::ParsedDname )* }
            )* )* )*
        );

        parse_err!(AllDataParseError,
            $( $( $(
                { $mtype $( $mn ::bits::name::ParsedDname )* }
            )* )* )*
            $( $( $(
                { $ptype $( $pn ::bits::name::ParsedDname )* }
            )* )* )*
        );
    }
}


macro_rules! parse_err {
    ( $err:ident, $( { $t:ident $( $x:ident $gen:ty )* } )* ) => {
        #[derive(Clone, Debug, Eq, Fail, PartialEq)]
        pub enum $err {
            $(
                #[fail(display="{}", _0)]
                $t(<$t $( <$gen> )* as ::bits::rdata::ParseRecordData>::Err),
            )*
            #[fail(display="short buffer")]
            ShortBuf,
        }

        impl From<::bits::parse::ShortBuf> for $err {
            fn from(_: ::bits::parse::ShortBuf) -> Self {
                $err::ShortBuf
            }
        }
    }
}

