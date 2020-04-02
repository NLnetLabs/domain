//! Macros for use in rdata definitions.
//!
//! These macros are not public but are used by the super module only. They
//! are here so that `mod.rs` doesn’t become too unwieldly.

macro_rules! rdata_types {
    ( $(
        $module:ident::{
            $(
                master {
                    $( $mtype:ident $( < $( $mn:ident ),* > )*, )*
                }
            )*
            $(
                pseudo {
                    $( $ptype:ident $( < $( $pn:ident ),* > )*, )*
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

        use crate::base::name::ParsedDname;


        //------------- MasterRecordData -------------------------------------

        /// Record data for all record types allowed in master files.
        ///
        /// This enum collects the record data types for all currently 
        /// implemented record types that are allowed to be included in master
        /// files.
        #[derive(Clone)]
        #[non_exhaustive]
        pub enum MasterRecordData<O, N> {
            $( $( $(
                $mtype($mtype $( < $( $mn ),* > )*),
            )* )* )*
            Other($crate::base::rdata::UnknownRecordData<O>),
        }

        impl<O, N> MasterRecordData<O, N> {
            fn rtype(&self) -> $crate::base::iana::Rtype {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(_) => {
                            <$mtype $( < $( $mn ),* > )*
                                as $crate::base::rdata::RtypeRecordData>::RTYPE
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.rtype(),
                }
            }
        }


        //--- From

        $( $( $(
            impl<O, N> From<$mtype $( < $( $mn ),* >)*>
            for MasterRecordData<O, N> {
                fn from(value: $mtype $( < $( $mn ),* >)*) -> Self {
                    MasterRecordData::$mtype(value)
                }
            }
        )* )* )*

        impl<O, N> From<$crate::base::rdata::UnknownRecordData<O>>
        for MasterRecordData<O, N> {
            fn from(value: $crate::base::rdata::UnknownRecordData<O>) -> Self {
                MasterRecordData::Other(value)
            }
        }


        //--- PartialEq and Eq

        impl<O, OO, N, NN> PartialEq<MasterRecordData<OO, NN>>
        for MasterRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::base::name::ToDname, NN: $crate::base::name::ToDname,
        {
            fn eq(&self, other: &MasterRecordData<OO, NN>) -> bool {
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
                    (
                        &MasterRecordData::Other(ref self_inner),
                        &MasterRecordData::Other(ref other_inner)
                    ) => {
                        self_inner.eq(other_inner)
                    }
                    _ => false
                }
            }
        }

        impl<O, N> Eq for MasterRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::base::name::ToDname { }


        //--- PartialOrd, Ord, and CanonicalOrd

        impl<O, OO, N, NN> PartialOrd<MasterRecordData<OO, NN>>
        for MasterRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::base::name::ToDname, NN: $crate::base::name::ToDname,
        {
            fn partial_cmp(
                &self,
                other: &MasterRecordData<OO, NN>
            ) -> Option<core::cmp::Ordering> {
                match (self, other) {
                    $( $( $(
                        (
                            &MasterRecordData::$mtype(ref self_inner),
                            &MasterRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.partial_cmp(other_inner)
                        }
                    )* )* )*
                    (
                        &MasterRecordData::Other(ref self_inner),
                        &MasterRecordData::Other(ref other_inner)
                    ) => {
                        self_inner.partial_cmp(other_inner)
                    }
                    _ => self.rtype().partial_cmp(&other.rtype())
                }
            }
        }

        impl<O, OO, N, NN> $crate::base::cmp::CanonicalOrd<MasterRecordData<OO, NN>>
        for MasterRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::base::cmp::CanonicalOrd<NN> + $crate::base::name::ToDname,
            NN: $crate::base::name::ToDname,
        {
            fn canonical_cmp(
                &self,
                other: &MasterRecordData<OO, NN>
            ) -> core::cmp::Ordering {
                match (self, other) {
                    $( $( $(
                        (
                            &MasterRecordData::$mtype(ref self_inner),
                            &MasterRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.canonical_cmp(other_inner)
                        }
                    )* )* )*
                    (
                        &MasterRecordData::Other(ref self_inner),
                        &MasterRecordData::Other(ref other_inner)
                    ) => {
                        self_inner.canonical_cmp(other_inner)
                    }
                    _ => self.rtype().cmp(&other.rtype())
                }
            }
        }

        //--- Hash
 
        impl<O, N> core::hash::Hash for MasterRecordData<O, N>
        where O: AsRef<[u8]>, N: core::hash::Hash {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            $crate::base::iana::Rtype::$mtype.hash(state);
                            inner.hash(state)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => {
                        inner.rtype().hash(state);
                        inner.data().as_ref().hash(state);
                    }
                }
            }
        }


        //--- Compose
        //
        //    No Parse or ParseAll because Other variant needs to know the
        //    record type.

        impl<O, N> $crate::base::octets::Compose for MasterRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::base::name::ToDname {
            fn compose<T: $crate::base::octets::OctetsBuilder>(
                &self,
                target: &mut T
            ) -> Result<(), $crate::base::octets::ShortBuf> {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compose(target)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => {
                        inner.compose(target)
                    }
                }
            }

            fn compose_canonical<T: $crate::base::octets::OctetsBuilder>(
                &self,
                target: &mut T
            ) -> Result<(), $crate::base::octets::ShortBuf> {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compose_canonical(target)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => {
                        inner.compose_canonical(target)
                    }
                }
            }
        }


        //--- RecordData and ParseRecordData

        impl<O, N> $crate::base::rdata::RecordData for MasterRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::base::name::ToDname
        {
            fn rtype(&self) -> $crate::base::iana::Rtype {
                self.rtype()
            }
        }

        impl<Ref: $crate::base::octets::OctetsRef>
        $crate::base::rdata::ParseRecordData<Ref>
        for MasterRecordData<Ref::Range, ParsedDname<Ref>> {
            fn parse_data(
                rtype: $crate::base::iana::Rtype,
                parser: &mut $crate::base::octets::Parser<Ref>,
            ) -> Result<Option<Self>, $crate::base::octets::ParseError> {
                use $crate::base::octets::Parse;

                match rtype {
                    $( $( $(
                        $crate::base::iana::Rtype::$mtype => {
                            Ok(Some(MasterRecordData::$mtype(
                                $mtype::parse(parser)?
                            )))
                        }
                    )* )* )*
                    _ => {
                        Ok($crate::base::rdata::UnknownRecordData::parse_data(
                            rtype, parser
                        )?.map(MasterRecordData::Other))
                    }
                }
            }
        }


        //--- (Scan) and Display

        #[cfg(feature="master")]
        impl MasterRecordData<
            bytes::Bytes, $crate::base::name::Dname<bytes::Bytes>
        > {
            pub fn scan<C>(rtype: $crate::base::iana::Rtype,
                           scanner: &mut $crate::master::scan::Scanner<C>)
                           -> Result<Self, $crate::master::scan::ScanError>
                        where C: $crate::master::scan::CharSource {
                use $crate::master::scan::Scan;

                match rtype {
                    $( $( $(
                        $crate::base::iana::Rtype::$mtype => {
                            $mtype::scan(scanner)
                                   .map(MasterRecordData::$mtype)
                        }
                    )* )* )*
                    _ => {
                        $crate::base::rdata::UnknownRecordData::scan(rtype, scanner)
                            .map(MasterRecordData::Other)
                    }
                }
            }
        }

        impl<O, N> core::fmt::Display for MasterRecordData<O, N>
        where
            O: AsRef<[u8]>,
            N: core::fmt::Display
        {
            fn fmt(&self, f: &mut core::fmt::Formatter)
                   -> core::fmt::Result {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.fmt(f)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.fmt(f),
                }
            }
        }

        //--- Debug

        impl<O, N> core::fmt::Debug for MasterRecordData<O, N>
        where
            O: AsRef<[u8]>,
            N: core ::fmt::Debug
        {
            fn fmt(&self, f: &mut core::fmt::Formatter)
                   -> core::fmt::Result {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            f.write_str(
                                concat!(
                                    "MasterRecordData::",
                                    stringify!($mtype),
                                    "("
                                )
                            )?;
                            core::fmt::Debug::fmt(inner, f)?;
                            f.write_str(")")
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => {
                        f.write_str("MasterRecordData::Other(")?;
                        core::fmt::Debug::fmt(inner, f)?;
                        f.write_str(")")
                    }
                }
            }
        }



        //------------- AllRecordData ----------------------------------------

        /// Record data for all record types.
        ///
        /// This enum collects the record data types for all currently 
        /// implemented record types.
        #[derive(Clone)]
        #[non_exhaustive]
        pub enum AllRecordData<O, N> {
            $( $( $(
                $mtype($mtype $( < $( $mn ),* > )*),
            )* )* )*
            $( $( $(
                $ptype($ptype $( < $( $pn ),* > )*),
            )* )* )*
            Opt($crate::base::opt::Opt<O>),
            Other($crate::base::rdata::UnknownRecordData<O>),
        }

        impl<O, N> AllRecordData<O, N> {
            fn rtype(&self) -> $crate::base::iana::Rtype {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(_) => {
                            <$mtype $( < $( $mn ),* > )*
                                as $crate::base::rdata::RtypeRecordData>::RTYPE
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(_) => {
                            <$ptype $( < $( $pn ),* > )*
                                as $crate::base::rdata::RtypeRecordData>::RTYPE
                        }
                    )* )* )*

                    AllRecordData::Opt(_) => $crate::base::iana::Rtype::Opt,
                    AllRecordData::Other(ref inner) => inner.rtype(),
                }
            }
        }

        //--- From and Into

        $( $( $(
            impl<O, N> From<$mtype $( < $( $mn ),* > )*>
            for AllRecordData<O, N> {
                fn from(value: $mtype $( < $( $mn ),* >)*) -> Self {
                    AllRecordData::$mtype(value)
                }
            }
        )* )* )*

        $( $( $(
            impl<O, N> From<$ptype $( < $( $pn ),* > )*>
            for AllRecordData<O, N> {
                fn from(value: $ptype $( < $( $pn ),* >)*) -> Self {
                    AllRecordData::$ptype(value)
                }
            }
        )* )* )*

        impl<O, N> From<$crate::base::opt::Opt<O>> for AllRecordData<O, N> {
            fn from(value: $crate::base::opt::Opt<O>) -> Self {
                AllRecordData::Opt(value)
            }
        }

        impl<O, N> From<$crate::base::rdata::UnknownRecordData<O>>
        for AllRecordData<O, N> {
            fn from(value: $crate::base::rdata::UnknownRecordData<O>) -> Self {
                AllRecordData::Other(value)
            }
        }

        impl<O, N> Into<Result<MasterRecordData<O, N>, Self>>
        for AllRecordData<O, N>
        {
            fn into(self) -> Result<MasterRecordData<O, N>, Self> {
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

        impl<O, OO, N, NN> PartialEq<AllRecordData<OO, NN>>
        for AllRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::base::name::ToDname, NN: $crate::base::name::ToDname
        {
            fn eq(&self, other: &AllRecordData<OO, NN>) -> bool {
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
                    (_, _) => false
                }
            }
        }

        impl<O, N> Eq for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::base::name::ToDname { }


        //--- Hash

        impl<O, N> core::hash::Hash for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: core::hash::Hash {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.rtype().hash(state);
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.hash(state)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.hash(state)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => {
                        inner.hash(state);
                    }
                    AllRecordData::Other(ref inner) => {
                        inner.data().as_ref().hash(state);
                    }
                }
            }
        }


        //--- Compose
        //
        //    No Parse or ParseAll because Other variant needs to know the
        //    record type.

        impl<O, N> $crate::base::octets::Compose for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::base::name::ToDname
        {
            fn compose<T: $crate::base::octets::OctetsBuilder>(
                &self,
                buf: &mut T
            ) -> Result<(), $crate::base::octets::ShortBuf> {
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
                }
            }

            fn compose_canonical<T: $crate::base::octets::OctetsBuilder>(
                &self,
                buf: &mut T
            ) -> Result<(), $crate::base::octets::ShortBuf> {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.compose_canonical(buf)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.compose_canonical(buf)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => {
                        inner.compose_canonical(buf)
                    }
                    AllRecordData::Other(ref inner) => {
                        inner.compose_canonical(buf)
                    }
                }
            }
        }


        //--- RecordData and ParseRecordData

        impl<O, N> $crate::base::rdata::RecordData for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::base::name::ToDname {
            fn rtype(&self) -> $crate::base::iana::Rtype {
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
                }
            }
        }

        impl<Ref: $crate::base::octets::OctetsRef>
        $crate::base::rdata::ParseRecordData<Ref>
        for AllRecordData<Ref::Range, ParsedDname<Ref>> {
            fn parse_data(
                rtype: $crate::base::iana::Rtype,
                parser: &mut $crate::base::octets::Parser<Ref>,
            ) -> Result<Option<Self>, $crate::base::octets::ParseError> {
                use $crate::base::octets::Parse;

                match rtype {
                    $( $( $(
                        $crate::base::iana::Rtype::$mtype => {
                            Ok(Some(AllRecordData::$mtype(
                                $mtype::parse(parser)?
                            )))
                        }
                    )* )* )*
                    $( $( $(
                        $crate::base::iana::Rtype::$ptype => {
                            Ok(Some(AllRecordData::$ptype(
                                $ptype::parse(parser)?
                            )))
                        }
                    )* )* )*
                    $crate::base::iana::Rtype::Opt => {
                        Ok(Some(AllRecordData::Opt(
                            $crate::base::opt::Opt::parse(parser)?
                        )))
                    }
                    _ => {
                        Ok($crate::base::rdata::UnknownRecordData::parse_data(
                            rtype, parser
                        )?.map(AllRecordData::Other))
                    }
                }
            }
        }

        
        //--- Display and Debug

        impl<O, N> core::fmt::Display for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: core::fmt::Display {
            fn fmt(
                &self, f: &mut core::fmt::Formatter
            ) -> core::fmt::Result {
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
                }
            }
        }

        impl<O, N> core::fmt::Debug for AllRecordData<O, N>
        where
            O: AsRef<[u8]>,
            N: core::fmt::Debug
        {
            fn fmt(
                &self, f: &mut core::fmt::Formatter
            ) -> core::fmt::Result {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            f.write_str(
                                concat!(
                                    "AllRecordData::",
                                    stringify!($mtype),
                                    "("
                                )
                            )?;
                            core::fmt::Debug::fmt(inner, f)?;
                            f.write_str(")")
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            f.write_str(
                                concat!(
                                    "AllRecordData::",
                                    stringify!($ptype),
                                    "("
                                )
                            )?;
                            core::fmt::Debug::fmt(inner, f)?;
                            f.write_str(")")
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => {
                        f.write_str("AllRecordData::Opt(")?;
                        core::fmt::Debug::fmt(inner, f)?;
                        f.write_str(")")
                    }
                    AllRecordData::Other(ref inner) => {
                        f.write_str("AllRecordData::Other(")?;
                        core::fmt::Debug::fmt(inner, f)?;
                        f.write_str(")")
                    }
                }
            }
        }

    }
}

