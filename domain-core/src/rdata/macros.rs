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

        use crate::name::ParsedDname;


        //------------- MasterRecordData -------------------------------------

        #[derive(Clone)]
        pub enum MasterRecordData<O, N> {
            $( $( $(
                $mtype($mtype $( < $( $mn ),* > )*),
            )* )* )*
            Other($crate::rdata::UnknownRecordData<O>),

            #[doc(hidden)]
            __Nonexhaustive(::void::Void),
        }

        impl<O, N> MasterRecordData<O, N> {
            fn rtype(&self) -> $crate::iana::Rtype {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(_) => {
                            <$mtype $( < $( $mn ),* > )*
                                as RtypeRecordData>::RTYPE
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => inner.rtype(),
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
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

        impl<O, N> From<$crate::rdata::UnknownRecordData<O>>
        for MasterRecordData<O, N> {
            fn from(value: $crate::rdata::UnknownRecordData<O>) -> Self {
                MasterRecordData::Other(value)
            }
        }


        //--- PartialEq and Eq

        impl<O, OO, N, NN> PartialEq<MasterRecordData<OO, NN>>
        for MasterRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::name::ToDname, NN: $crate::name::ToDname,
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
                    (_, &MasterRecordData::__Nonexhaustive(_))
                        => unreachable!(),
                    (&MasterRecordData::__Nonexhaustive(_), _)
                        => unreachable!(),
                    _ => false
                }
            }
        }

        impl<O, N> Eq for MasterRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::name::ToDname { }


        //--- PartialOrd, Ord, and CanonicalOrd

        impl<O, OO, N, NN> PartialOrd<MasterRecordData<OO, NN>>
        for MasterRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::name::ToDname, NN: $crate::name::ToDname,
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
                    (_, &MasterRecordData::__Nonexhaustive(_))
                        => unreachable!(),
                    (&MasterRecordData::__Nonexhaustive(_), _)
                        => unreachable!(),
                    _ => self.rtype().partial_cmp(&other.rtype())
                }
            }
        }

        impl<O, OO, N, NN> CanonicalOrd<MasterRecordData<OO, NN>>
        for MasterRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: CanonicalOrd<NN> + $crate::name::ToDname,
            NN: $crate::name::ToDname,
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
                    (_, &MasterRecordData::__Nonexhaustive(_))
                        => unreachable!(),
                    (&MasterRecordData::__Nonexhaustive(_), _)
                        => unreachable!(),
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
                            $crate::iana::Rtype::$mtype.hash(state);
                            inner.hash(state)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => {
                        inner.rtype().hash(state);
                        inner.data().as_ref().hash(state);
                    }
                    MasterRecordData::__Nonexhaustive(_) => unreachable!()
                }
            }
        }


        //--- Compose
        //
        //    No Parse or ParseAll because Other variant needs to know the
        //    record type.

        impl<O, N> $crate::octets::Compose for MasterRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::name::ToDname {
            fn compose<T: $crate::octets::OctetsBuilder>(
                &self,
                target: &mut T
            ) -> Result<(), $crate::octets::ShortBuf> {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compose(target)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => {
                        inner.compose(target)
                    }
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }

            fn compose_canonical<T: $crate::octets::OctetsBuilder>(
                &self,
                target: &mut T
            ) -> Result<(), $crate::octets::ShortBuf> {
                match *self {
                    $( $( $(
                        MasterRecordData::$mtype(ref inner) => {
                            inner.compose_canonical(target)
                        }
                    )* )* )*
                    MasterRecordData::Other(ref inner) => {
                        inner.compose_canonical(target)
                    }
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }


        //--- RecordData and ParseRecordData

        impl<O, N> $crate::rdata::RecordData for MasterRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::name::ToDname
        {
            fn rtype(&self) -> $crate::iana::Rtype {
                self.rtype()
            }
        }

        impl<Ref: OctetsRef> $crate::rdata::ParseRecordData<Ref>
        for MasterRecordData<Ref::Range, ParsedDname<Ref>> {
            fn parse_data(
                rtype: $crate::iana::Rtype,
                parser: &mut $crate::parse::Parser<Ref>,
            ) -> Result<Option<Self>, ParseError> {
                use $crate::parse::Parse;

                match rtype {
                    $( $( $(
                        $crate::iana::Rtype::$mtype => {
                            Ok(Some(MasterRecordData::$mtype(
                                $mtype::parse(parser)?
                            )))
                        }
                    )* )* )*
                    _ => {
                        Ok($crate::rdata::UnknownRecordData::parse_data(
                            rtype, parser
                        )?.map(MasterRecordData::Other))
                    }
                }
            }
        }


        //--- (Scan) and Display

        #[cfg(feature="bytes")]
        impl MasterRecordData<
            bytes::Bytes, $crate::name::Dname<bytes::Bytes>
        > {
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
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
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
                    MasterRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }



        //------------- AllRecordData ----------------------------------------

        #[derive(Clone)]
        pub enum AllRecordData<O, N> {
            $( $( $(
                $mtype($mtype $( < $( $mn ),* > )*),
            )* )* )*
            $( $( $(
                $ptype($ptype $( < $( $pn ),* > )*),
            )* )* )*
            Opt($crate::opt::Opt<O>),
            Other($crate::rdata::UnknownRecordData<O>),

            #[doc(hidden)]
            __Nonexhaustive(::void::Void),
        }

        impl<O, N> AllRecordData<O, N> {
            fn rtype(&self) -> $crate::iana::Rtype {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(_) => {
                            <$mtype $( < $( $mn ),* > )*
                                as RtypeRecordData>::RTYPE
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(_) => {
                            <$ptype $( < $( $pn ),* > )*
                                as RtypeRecordData>::RTYPE
                        }
                    )* )* )*

                    AllRecordData::Opt(_) => Rtype::Opt,
                    AllRecordData::Other(ref inner) => inner.rtype(),
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
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

        impl<O, N> From<$crate::opt::Opt<O>> for AllRecordData<O, N> {
            fn from(value: $crate::opt::Opt<O>) -> Self {
                AllRecordData::Opt(value)
            }
        }

        impl<O, N> From<$crate::rdata::UnknownRecordData<O>>
        for AllRecordData<O, N> {
            fn from(value: $crate::rdata::UnknownRecordData<O>) -> Self {
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
            N: $crate::name::ToDname, NN: $crate::name::ToDname
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
                    (_, &AllRecordData::__Nonexhaustive(_))
                        => unreachable!(),
                    (&AllRecordData::__Nonexhaustive(_), _)
                        => unreachable!(),
                    (_, _) => false
                }
            }
        }

        impl<O, N> Eq for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::name::ToDname { }


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
                    AllRecordData::__Nonexhaustive(_) => unreachable!()
                }
            }
        }


        //--- Compose
        //
        //    No Parse or ParseAll because Other variant needs to know the
        //    record type.

        impl<O, N> $crate::octets::Compose for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::name::ToDname
        {
            fn compose<T: $crate::octets::OctetsBuilder>(
                &self,
                buf: &mut T
            ) -> Result<(), $crate::octets::ShortBuf> {
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

            fn compose_canonical<T: $crate::octets::OctetsBuilder>(
                &self,
                buf: &mut T
            ) -> Result<(), $crate::octets::ShortBuf> {
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
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }


        //--- RecordData and ParseRecordData

        impl<O, N> $crate::rdata::RecordData for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::name::ToDname {
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

        impl<Ref: OctetsRef> $crate::rdata::ParseRecordData<Ref>
        for AllRecordData<Ref::Range, ParsedDname<Ref>> {
            fn parse_data(
                rtype: $crate::iana::Rtype,
                parser: &mut $crate::parse::Parser<Ref>,
            ) -> Result<Option<Self>, ParseError> {
                use $crate::parse::Parse;

                match rtype {
                    $( $( $(
                        $crate::iana::Rtype::$mtype => {
                            Ok(Some(AllRecordData::$mtype(
                                $mtype::parse(parser)?
                            )))
                        }
                    )* )* )*
                    $( $( $(
                        $crate::iana::Rtype::$ptype => {
                            Ok(Some(AllRecordData::$ptype(
                                $ptype::parse(parser)?
                            )))
                        }
                    )* )* )*
                    $crate::iana::Rtype::Opt => {
                        Ok(Some(AllRecordData::Opt(
                            $crate::opt::Opt::parse(parser)?
                        )))
                    }
                    _ => {
                        Ok($crate::rdata::UnknownRecordData::parse_data(
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
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
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
                    AllRecordData::__Nonexhaustive(_) => unreachable!(),
                }
            }
        }

    }
}

