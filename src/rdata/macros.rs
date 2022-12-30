//! Macros for use in rdata definitions.
//!
//! These macros are not public but are used by the super module only. They
//! are here so that `mod.rs` doesn’t become too unwieldly.

macro_rules! rdata_types {
    ( $(
        $module:ident::{
            $(
                zone {
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

        use crate::base::name::{ParsedDname, PushError, ToDname};
        use crate::base::octets::{
            Composer, EmptyBuilder, FromBuilder, OctetsFrom, OctetsInto
        };
        use crate::base::rdata::ComposeRecordData;


        //------------- ZoneRecordData ---------------------------------------

        /// Record data for all record types allowed in zone files.
        ///
        /// This enum collects the record data types for all currently
        /// implemented record types that are allowed to be included in zone
        /// files.
        #[derive(Clone)]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize)
        )]
        #[cfg_attr(
            feature = "serde",
            serde(bound(
                serialize = "
                    O: AsRef<[u8]> + crate::base::octets::SerializeOctets,
                    N: serde::Serialize,
                ",
                deserialize = "
                    O: crate::base::octets::FromBuilder
                        + crate::base::octets::DeserializeOctets<'de>,
                    <O as crate::base::octets::FromBuilder>::Builder:
                          crate::base::octets::EmptyBuilder
                        + octseq::builder::Truncate
                        + AsRef<[u8]> + AsMut<[u8]>,
                    N: serde::Deserialize<'de>,
                ",
            ))
        )]
        #[non_exhaustive]
        pub enum ZoneRecordData<O, N> {
            $( $( $(
                $mtype($mtype $( < $( $mn ),* > )*),
            )* )* )*
            Unknown($crate::base::rdata::UnknownRecordData<O>),
        }

        impl<O, N> ZoneRecordData<O, N> {
            fn rtype(&self) -> $crate::base::iana::Rtype {
                use $crate::base::rdata::RecordData;

                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            inner.rtype()
                            /*
                            <$mtype $( < $( $mn ),* > )*
                                as $crate::base::rdata::RtypeRecordData>::RTYPE
                            */
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => inner.rtype(),
                }
            }
        }

        impl<'a, Octs> ZoneRecordData<Octs::Range<'a>, ParsedDname<'a, Octs>>
        where
            Octs: crate::base::octets::Octets,
        {
            pub fn flatten_into<Target>(
                self,
            ) -> Result<
                ZoneRecordData<Target, crate::base::Dname<Target>>,
                PushError
            >
            where
                Target: OctetsFrom<Octs::Range<'a>> + FromBuilder,
                <Target as FromBuilder>::Builder: EmptyBuilder,
                PushError: From<<Target as OctetsFrom<Octs::Range<'a>>>::Error>
            {
                match self {
                    $( $( $(
                        ZoneRecordData::$mtype(inner) => {
                            Ok(ZoneRecordData::$mtype(inner.flatten_into()?))
                        }
                    )* )* )*
                        ZoneRecordData::Unknown(inner) => {
                            Ok(ZoneRecordData::Unknown(
                                inner.try_octets_into()?
                            ))
                        }
                }

            }
        }

        //--- OctetsFrom

        impl<Octets, SrcOctets, Name, SrcName>
            $crate::base::octets::OctetsFrom<
                ZoneRecordData<SrcOctets, SrcName>
            >
            for ZoneRecordData<Octets, Name>
        where
            Octets: $crate::base::octets::OctetsFrom<SrcOctets>,
            Name: $crate::base::octets::OctetsFrom<
                SrcName, Error = Octets::Error
            >,
        {
            type Error = Octets::Error;

            fn try_octets_from(
                source: ZoneRecordData<SrcOctets, SrcName>
            ) -> Result<Self, Self::Error> {
                match source {
                    $( $( $(
                        ZoneRecordData::$mtype(inner) => {
                            inner.convert_octets().map(
                                ZoneRecordData::$mtype
                            )
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(inner) => {
                        Ok(ZoneRecordData::Unknown(
                            match
                                $crate::base::rdata::
                                UnknownRecordData::try_octets_from(inner)
                            {
                                Ok(ok) => ok,
                                Err(err) => return Err(err.into())
                            }
                        ))
                    }
                }
            }
        }


        //--- From

        $( $( $(
            impl<O, N> From<$mtype $( < $( $mn ),* >)*>
            for ZoneRecordData<O, N> {
                fn from(value: $mtype $( < $( $mn ),* >)*) -> Self {
                    ZoneRecordData::$mtype(value)
                }
            }
        )* )* )*

        impl<O, N> From<$crate::base::rdata::UnknownRecordData<O>>
        for ZoneRecordData<O, N> {
            fn from(value: $crate::base::rdata::UnknownRecordData<O>) -> Self {
                ZoneRecordData::Unknown(value)
            }
        }


        //--- PartialEq and Eq

        impl<O, OO, N, NN> PartialEq<ZoneRecordData<OO, NN>>
        for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::base::name::ToDname, NN: $crate::base::name::ToDname,
        {
            fn eq(&self, other: &ZoneRecordData<OO, NN>) -> bool {
                match (self, other) {
                    $( $( $(
                        (
                            &ZoneRecordData::$mtype(ref self_inner),
                            &ZoneRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.eq(other_inner)
                        }
                    )* )* )*
                    (
                        &ZoneRecordData::Unknown(ref self_inner),
                        &ZoneRecordData::Unknown(ref other_inner)
                    ) => {
                        self_inner.eq(other_inner)
                    }
                    _ => false
                }
            }
        }

        impl<O, N> Eq for ZoneRecordData<O, N>
        where O: AsRef<[u8]>, N: $crate::base::name::ToDname { }


        //--- PartialOrd, Ord, and CanonicalOrd

        impl<O, OO, N, NN> PartialOrd<ZoneRecordData<OO, NN>>
        for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::base::name::ToDname, NN: $crate::base::name::ToDname,
        {
            fn partial_cmp(
                &self,
                other: &ZoneRecordData<OO, NN>
            ) -> Option<core::cmp::Ordering> {
                match (self, other) {
                    $( $( $(
                        (
                            &ZoneRecordData::$mtype(ref self_inner),
                            &ZoneRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.partial_cmp(other_inner)
                        }
                    )* )* )*
                    (
                        &ZoneRecordData::Unknown(ref self_inner),
                        &ZoneRecordData::Unknown(ref other_inner)
                    ) => {
                        self_inner.partial_cmp(other_inner)
                    }
                    _ => self.rtype().partial_cmp(&other.rtype())
                }
            }
        }

        impl<O, OO, N, NN>
        $crate::base::cmp::CanonicalOrd<ZoneRecordData<OO, NN>>
        for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: $crate::base::cmp::CanonicalOrd<NN>
                + $crate::base::name::ToDname,
            NN: $crate::base::name::ToDname,
        {
            fn canonical_cmp(
                &self,
                other: &ZoneRecordData<OO, NN>
            ) -> core::cmp::Ordering {
                match (self, other) {
                    $( $( $(
                        (
                            &ZoneRecordData::$mtype(ref self_inner),
                            &ZoneRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.canonical_cmp(other_inner)
                        }
                    )* )* )*
                    (
                        &ZoneRecordData::Unknown(ref self_inner),
                        &ZoneRecordData::Unknown(ref other_inner)
                    ) => {
                        self_inner.canonical_cmp(other_inner)
                    }
                    _ => self.rtype().cmp(&other.rtype())
                }
            }
        }

        //--- Hash

        impl<O, N> core::hash::Hash for ZoneRecordData<O, N>
        where O: AsRef<[u8]>, N: core::hash::Hash {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            $crate::base::iana::Rtype::$mtype.hash(state);
                            inner.hash(state)
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => {
                        inner.rtype().hash(state);
                        inner.data().as_ref().hash(state);
                    }
                }
            }
        }

        //--- RecordData, ParseRecordData, and ComposeRecordData

        impl<O, N> $crate::base::rdata::RecordData for ZoneRecordData<O, N> {
            fn rtype(&self) -> $crate::base::iana::Rtype {
                ZoneRecordData::rtype(self)
            }
        }

        impl<'a, Octs: $crate::base::octets::Octets>
        $crate::base::rdata::ParseRecordData<'a, Octs>
        for ZoneRecordData<Octs::Range<'a>, ParsedDname<'a, Octs>> {
            fn parse_rdata(
                rtype: $crate::base::iana::Rtype,
                parser: &mut $crate::base::octets::Parser<'a, Octs>,
            ) -> Result<Option<Self>, $crate::base::octets::ParseError> {
                use $crate::base::octets::Parse;

                match rtype {
                    $( $( $(
                        $crate::base::iana::Rtype::$mtype => {
                            Ok(Some(ZoneRecordData::$mtype(
                                $mtype::parse(parser)?
                            )))
                        }
                    )* )* )*
                    _ => {
                        Ok($crate::base::rdata::UnknownRecordData::parse_rdata(
                            rtype, parser
                        )?.map(ZoneRecordData::Unknown))
                    }
                }
            }
        }

        impl<Octs, Name> ComposeRecordData for ZoneRecordData<Octs, Name>
        where Octs: AsRef<[u8]>, Name: ToDname {
            fn rdlen(&self, compress: bool) -> Option<u16> {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            inner.rdlen(compress)
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => {
                        inner.rdlen(compress)
                    }
                }
            }

            fn compose_rdata<Target: Composer + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            inner.compose_rdata(target)
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => {
                        inner.compose_rdata(target)
                    }
                }
            }

            fn compose_canonical_rdata<Target: Composer + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            inner.compose_canonical_rdata(target)
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => {
                        inner.compose_canonical_rdata(target)
                    }
                }
            }
        }


        //--- (Scan) and Display

        impl<Octets: AsRef<[u8]>, Name> ZoneRecordData<Octets, Name> {
            /// Scans a value of the given rtype.
            ///
            /// If the record data is given via the notation for unknown
            /// record types, the returned value will be of the
            /// `ZoneRecordData::Unknown(_)` variant.
            pub fn scan<S>(
                rtype: $crate::base::iana::Rtype,
                scanner: &mut S
            ) -> Result<Self, S::Error>
            where
                S: $crate::base::scan::Scanner<Octets = Octets, Dname = Name>
            {
                use $crate::base::rdata::{UnknownRecordData};
                use $crate::base::scan::{Scan, ScannerError};

                if scanner.scan_opt_unknown_marker()? {
                    UnknownRecordData::scan_without_marker(
                        rtype, scanner
                    ).map(ZoneRecordData::Unknown)
                }
                else {
                    match rtype {
                        $( $( $(
                            $crate::base::iana::Rtype::$mtype => {
                                $mtype::scan(
                                    scanner
                                ).map(ZoneRecordData::$mtype)
                            }
                        )* )* )*
                        _ => {
                            Err(S::Error::custom(
                                "unknown record type with concrete data"
                            ))
                        }
                    }
                }
            }
        }

        impl<O, N> core::fmt::Display for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>,
            N: core::fmt::Display
        {
            fn fmt(&self, f: &mut core::fmt::Formatter)
                   -> core::fmt::Result {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            inner.fmt(f)
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => inner.fmt(f),
                }
            }
        }

        //--- Debug

        impl<O, N> core::fmt::Debug for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>,
            N: core ::fmt::Debug
        {
            fn fmt(&self, f: &mut core::fmt::Formatter)
                   -> core::fmt::Result {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            f.write_str(
                                concat!(
                                    "ZoneRecordData::",
                                    stringify!($mtype),
                                    "("
                                )
                            )?;
                            core::fmt::Debug::fmt(inner, f)?;
                            f.write_str(")")
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => {
                        f.write_str("ZoneRecordData::Unknown(")?;
                        core::fmt::Debug::fmt(inner, f)?;
                        f.write_str(")")
                    }
                }
            }
        }

        /*
        //--- Serialize and Deserialize

        #[cfg(feature = "serde")]
        impl<O, N> serde::Serialize for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]> + crate::base::octets::SerializeOctets,
            N: serde::Serialize,
        {
            fn serialize<S: serde::Serializer>(
                &self, serializer: S
            ) -> Result<S::Ok, S::Error> {
                use crate::base::iana::Rtype;

                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            serializer.serialize_newtype_variant(
                                "ZoneRecordData",
                                Rtype::$mtype.to_int().into(),
                                stringify!($mtype),
                                inner
                            )
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => {
                        serializer.serialize_newtype_variant(
                            "ZoneRecordData",
                            u32::MAX,
                            "Unknown",
                            inner
                        )
                    }
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, O, N> serde::Deserialize<'de> for ZoneRecordData<O, N>
        where
            O: crate::base::octets::FromBuilder
                + crate::base::octets::DeserializeOctets<'de>,
            <O as crate::base::octets::FromBuilder>::Builder:
                crate::base::octets::OctetsBuilder<Octets = O>
                + crate::base::octets::EmptyBuilder,
            N: serde::Deserialize<'de>,
        {
            fn deserialize<D: serde::Deserializer<'de>>(
                _deserializer: D
            ) -> Result<Self, D::Error> {
                unimplemented!()
            }
        }
        */

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
            Unknown($crate::base::rdata::UnknownRecordData<O>),
        }

        impl<O, N> AllRecordData<O, N> {
            fn rtype(&self) -> $crate::base::iana::Rtype {
                use $crate::base::rdata::RecordData;

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

                    /*
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
                    */

                    AllRecordData::Opt(_) => $crate::base::iana::Rtype::Opt,
                    AllRecordData::Unknown(ref inner) => inner.rtype(),
                }
            }
        }

        impl<'a, Octs> AllRecordData<Octs::Range<'a>, ParsedDname<'a, Octs>>
        where
            Octs: crate::base::octets::Octets,
        {
            pub fn flatten_into<Target>(
                self,
            ) -> Result<
                AllRecordData<Target, crate::base::Dname<Target>>,
                PushError
            >
            where
                Target: OctetsFrom<Octs::Range<'a>> + FromBuilder,
                <Target as FromBuilder>::Builder: EmptyBuilder,
                PushError: From<<Target as OctetsFrom<Octs::Range<'a>>>::Error>
            {
                match self {
                    $( $( $(
                        AllRecordData::$mtype(inner) => {
                            Ok(AllRecordData::$mtype(inner.flatten_into()?))
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(inner) => {
                            Ok(AllRecordData::$ptype(inner.flatten_into()?))
                        }
                    )* )* )*
                    AllRecordData::Opt(inner) => {
                        Ok(AllRecordData::Opt(inner.try_octets_into()?))
                    }
                    AllRecordData::Unknown(inner) => {
                        Ok(AllRecordData::Unknown(inner.try_octets_into()?))
                    }
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
            fn from(
                value: $crate::base::rdata::UnknownRecordData<O>
            ) -> Self {
                AllRecordData::Unknown(value)
            }
        }

        impl<O, N> From<AllRecordData<O, N>>
        for Result<ZoneRecordData<O, N>, AllRecordData<O, N>> {
            fn from(
                value: AllRecordData<O, N>
            ) -> Result<ZoneRecordData<O, N>, AllRecordData<O, N>> {
                match value {
                    $( $( $(
                        AllRecordData::$mtype(inner) => {
                            Ok(ZoneRecordData::$mtype(inner))
                        }
                    )* )* )*
                    AllRecordData::Unknown(inner) => {
                        Ok(ZoneRecordData::Unknown(inner))
                    }
                    value => Err(value),
                }
            }
        }

        //--- OctetsFrom

        impl<Octets, SrcOctets, Name, SrcName>
            $crate::base::octets::OctetsFrom<
                AllRecordData<SrcOctets, SrcName>
            >
            for AllRecordData<Octets, Name>
        where
            Octets: $crate::base::octets::OctetsFrom<SrcOctets>,
            Name: $crate::base::octets::OctetsFrom<
                SrcName, Error = Octets::Error,
            >,
        {
            type Error = Octets::Error;

            fn try_octets_from(
                source: AllRecordData<SrcOctets, SrcName>
            ) -> Result<Self, Self::Error> {
                match source {
                    $( $( $(
                        AllRecordData::$mtype(inner) => {
                            inner.convert_octets().map(
                                AllRecordData::$mtype
                            )
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(inner) => {
                            inner.convert_octets().map(
                                AllRecordData::$ptype
                            )
                        }
                    )* )* )*
                    AllRecordData::Opt(inner) => {
                        Ok(AllRecordData::Opt(
                            $crate::base::opt::Opt::try_octets_from(inner)?
                        ))
                    }
                    AllRecordData::Unknown(inner) => {
                        Ok(AllRecordData::Unknown(
                            $crate::base::rdata::UnknownRecordData
                                ::try_octets_from(inner)?
                        ))
                    }
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
                    AllRecordData::Unknown(ref inner) => {
                        inner.data().as_ref().hash(state);
                    }
                }
            }
        }

        //--- RecordData and ParseRecordData

        impl<O, N> $crate::base::rdata::RecordData for AllRecordData<O, N> {
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
                    AllRecordData::Unknown(ref inner) => inner.rtype(),
                }
            }
        }

        impl<'a, Octs: $crate::base::octets::Octets>
        $crate::base::rdata::ParseRecordData<'a, Octs>
        for AllRecordData<Octs::Range<'a>, ParsedDname<'a, Octs>> {
            fn parse_rdata(
                rtype: $crate::base::iana::Rtype,
                parser: &mut $crate::base::octets::Parser<'a, Octs>,
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
                        Ok($crate::base::rdata::UnknownRecordData::parse_rdata(
                            rtype, parser
                        )?.map(AllRecordData::Unknown))
                    }
                }
            }
        }

        impl<Octs, Name> ComposeRecordData for AllRecordData<Octs, Name>
        where Octs: AsRef<[u8]>, Name: ToDname {
            fn rdlen(&self, compress: bool) -> Option<u16> {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.rdlen(compress)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.rdlen(compress)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => {
                        inner.rdlen(compress)
                    }
                    AllRecordData::Unknown(ref inner) => {
                        inner.rdlen(compress)
                    }
                }
            }

            fn compose_rdata<Target: Composer + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.compose_rdata(target)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.compose_rdata(target)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => {
                        inner.compose_rdata(target)
                    }
                    AllRecordData::Unknown(ref inner) => {
                        inner.compose_rdata(target)
                    }
                }
            }

            fn compose_canonical_rdata<Target: Composer + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.compose_canonical_rdata(target)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.compose_canonical_rdata(target)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => {
                        inner.compose_canonical_rdata(target)
                    }
                    AllRecordData::Unknown(ref inner) => {
                        inner.compose_canonical_rdata(target)
                    }
                }
            }
        }


        //--- Display and Debug

        impl<O, N> core::fmt::Display for AllRecordData<O, N>
        where O: crate::base::octets::Octets, N: core::fmt::Display {
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
                    AllRecordData::Unknown(ref inner) => inner.fmt(f),
                }
            }
        }

        impl<O, N> core::fmt::Debug for AllRecordData<O, N>
        where O: crate::base::octets::Octets, N: core::fmt::Debug {
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
                    AllRecordData::Unknown(ref inner) => {
                        f.write_str("AllRecordData::Unknown(")?;
                        core::fmt::Debug::fmt(inner, f)?;
                        f.write_str(")")
                    }
                }
            }
        }

    }
}

//------------ dname_type! --------------------------------------------------

/// A macro for implementing a record data type with a single domain name.
///
/// Implements some basic methods plus the `RecordData`, `FlatRecordData`,
/// and `Display` traits.
macro_rules! dname_type_base {
    ($(#[$attr:meta])* ( $target:ident, $rtype:ident, $field:ident ) ) => {
        $(#[$attr])*
        #[derive(Clone, Debug)]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize)
        )]
        pub struct $target<N: ?Sized> {
            $field: N
        }

        impl<N> $target<N> {
            pub fn new($field: N) -> Self {
                $target { $field }
            }

            pub fn $field(&self) -> &N {
                &self.$field
            }

            pub(super) fn convert_octets<Target: OctetsFrom<N>>(
                self
            ) -> Result<$target<Target>, Target::Error> {
                Target::try_octets_from(self.$field).map($target::new)
            }
        }

        impl<'a, Octs> $target<ParsedDname<'a, Octs>>
        where
            Octs: crate::base::octets::Octets,
        {
            pub fn flatten_into<Octets>(
                self,
            ) -> Result<$target<crate::base::Dname<Octets>>, PushError>
            where
                Octets: OctetsFrom<Octs::Range<'a>> + FromBuilder,
                <Octets as FromBuilder>::Builder: EmptyBuilder,
            {
                Ok($target::new(self.$field.flatten_into()?))
            }
        }

        //--- From and FromStr

        impl<N> From<N> for $target<N> {
            fn from(name: N) -> Self {
                Self::new(name)
            }
        }

        impl<N: FromStr> FromStr for $target<N> {
            type Err = N::Err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                N::from_str(s).map(Self::new)
            }
        }


        //--- OctetsFrom

        impl<Name, SrcName> OctetsFrom<$target<SrcName>> for $target<Name>
        where Name: OctetsFrom<SrcName> {
            type Error = Name::Error;

            fn try_octets_from(
                source: $target<SrcName>
            ) -> Result<Self, Self::Error> {
                Name::try_octets_from(source.$field).map(|name| {
                    Self::new(name)
                })
            }
        }


        //--- PartialEq and Eq

        impl<N, NN> PartialEq<$target<NN>> for $target<N>
        where N: ToDname, NN: ToDname {
            fn eq(&self, other: &$target<NN>) -> bool {
                self.$field.name_eq(&other.$field)
            }
        }

        impl<N: ToDname> Eq for $target<N> { }


        //--- PartialOrd and Ord
        //
        // For CanonicalOrd, see below.

        impl<N, NN> PartialOrd<$target<NN>> for $target<N>
        where N: ToDname, NN: ToDname {
            fn partial_cmp(&self, other: &$target<NN>) -> Option<Ordering> {
                Some(self.$field.name_cmp(&other.$field))
            }
        }

        impl<N: ToDname> Ord for $target<N> {
            fn cmp(&self, other: &Self) -> Ordering {
                self.$field.name_cmp(&other.$field)
            }
        }

        //--- Hash

        impl<N: hash::Hash> hash::Hash for $target<N> {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                self.$field.hash(state)
            }
        }

        //--- Parse

        impl<'a, Octs: Octets + ?Sized> Parse<'a, Octs>
        for $target<ParsedDname<'a, Octs>> {
            fn parse(
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Self, ParseError> {
                ParsedDname::parse(parser).map(Self::new)
            }

            fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
                ParsedDname::skip(parser).map_err(Into::into)
            }
        }

        //--- RecordData, ParseRecordData

        impl<N> $crate::base::rdata::RecordData for $target<N> {
            fn rtype(&self) -> $crate::base::iana::Rtype {
                $crate::base::iana::Rtype::$rtype
            }
        }

        impl<'a, Octs> $crate::base::rdata::ParseRecordData<'a, Octs>
        for $target<$crate::base::name::ParsedDname<'a, Octs>>
        where Octs: octseq::octets::Octets + ?Sized{
            fn parse_rdata(
                rtype: $crate::base::iana::Rtype,
                parser: &mut octseq::parse::Parser<'a, Octs>,
            ) -> Result<Option<Self>, $crate::base::wire::ParseError> {
                if rtype == $crate::base::iana::Rtype::$rtype {
                    Self::parse(parser).map(Some)
                }
                else {
                    Ok(None)
                }
            }
        }

        //--- Scan and Display

        impl<N, S> crate::base::scan::Scan<S> for $target<N>
        where S: crate::base::scan::Scanner<Dname = N> {
            fn scan(scanner: &mut S) -> Result<Self, S::Error> {
                scanner.scan_dname().map(Self::new)
            }
        }

        impl<N: fmt::Display> fmt::Display for $target<N> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}.", self.$field)
            }
        }

        //--- Deref

        impl<N> ops::Deref for $target<N> {
            type Target = N;

            fn deref(&self) -> &Self::Target {
                &self.$field
            }
        }
    }
}

macro_rules! dname_type_well_known {
    ($(#[$attr:meta])* ( $target:ident, $rtype:ident, $field:ident ) ) => {
        dname_type_base! {
            $( #[$attr] )*
            ($target, $rtype, $field)
        }

        impl<N: ToDname> $crate::base::rdata::ComposeRecordData
        for $target<N> {
            fn rdlen(&self, compress: bool) -> Option<u16> {
                if compress {
                    None
                }
                else {
                    Some(self.compose_len())
                }
            }

            fn compose_rdata<Target: $crate::base::wire::Composer + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                if target.can_compress() {
                    target.append_compressed_dname(&self.$field)
                }
                else {
                    self.$field.compose(target)
                }
            }

            fn compose_canonical_rdata<Target>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError>
            where Target: $crate::base::wire::Composer + ?Sized {
                self.$field.compose_canonical(target)
            }
        }

        impl<N: ToDname, NN: ToDname> CanonicalOrd<$target<NN>> for $target<N> {
            fn canonical_cmp(&self, other: &$target<NN>) -> Ordering {
                self.$field.lowercase_composed_cmp(&other.$field)
            }
        }
    }
}

macro_rules! dname_type_canonical {
    ($(#[$attr:meta])* ( $target:ident, $rtype:ident, $field:ident ) ) => {
        dname_type_base! {
            $( #[$attr] )*
            ($target, $rtype, $field)
        }

        impl<N: ToDname> $crate::base::rdata::ComposeRecordData
        for $target<N> {
            fn rdlen(&self, _compress: bool) -> Option<u16> {
                Some(self.compose_len())
            }

            fn compose_rdata<Target: $crate::base::wire::Composer + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                self.$field.compose(target)
            }

            fn compose_canonical_rdata<Target>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError>
            where Target: $crate::base::wire::Composer + ?Sized {
                self.$field.compose_canonical(target)
            }
        }

        impl<N: ToDname, NN: ToDname> CanonicalOrd<$target<NN>> for $target<N> {
            fn canonical_cmp(&self, other: &$target<NN>) -> Ordering {
                self.$field.lowercase_composed_cmp(&other.$field)
            }
        }
    }
}

#[allow(unused_macros)]
macro_rules! dname_type {
    ($(#[$attr:meta])* ( $target:ident, $rtype:ident, $field:ident ) ) => {
        dname_type_base! {
            $( #[$attr] )*
            ($target, $rtype, $field)
        }

        impl<N: ToDname> $crate::base::rdata::ComposeRecordData
        for $target<N> {
            fn rdlen(&self, _compress: bool) -> Option<u16> {
                Some(self.compose_len)
            }

            fn compose_rdata<Target: $crate::base::wire::Composer + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                self.$field.compose(target)
            }

            fn compose_canonical_rdata<Target>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError>
            where Target: $crate::base::wire::Composer + ?Sized {
                self.$field.compose(target)
            }
        }

        impl<N: ToDname, NN: ToDname> CanonicalOrd<$target<NN>> for $target<N> {
            fn canonical_cmp(&self, other: &$target<NN>) -> Ordering {
                self.$field.name_cmp(&other.$field)
            }
        }
    }
}

