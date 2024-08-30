//! Macros for use in rdata definitions.
//!
//! These macros are not public but are used by the super module only. They
//! are here so that `mod.rs` doesn’t become too unwieldly.

macro_rules! rdata_types {
    ( $(
        $module:ident::{
            $(
                zone {
                    $( $mtype:ident $( < $( $mn:ident ),* > ),* $(,)? )*
                }
            )*
            $(
                pseudo {
                    $( $ptype:ident $( < $( $pn:ident ),* > ),*  $(,)? )*
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

        $(
            pub mod $module;
        )*

        use core::{fmt, hash};
        use crate::base::cmp::CanonicalOrd;
        use crate::base::iana::Rtype;
        use crate::base::name::{FlattenInto, ParsedName, ToName};
        use crate::base::opt::Opt;
        use crate::base::rdata::{
            ComposeRecordData, ParseAnyRecordData, ParseRecordData,
            RecordData, UnknownRecordData,
        };
        use crate::base::scan::ScannerError;
        use crate::base::wire::{Composer, ParseError};
        use octseq::octets::{Octets, OctetsFrom};
        use octseq::parse::Parser;


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
                    O: AsRef<[u8]> + octseq::serde::SerializeOctets,
                    N: serde::Serialize,
                ",
                deserialize = "
                    O: octseq::builder::FromBuilder
                        + octseq::serde::DeserializeOctets<'de>,
                    <O as octseq::builder::FromBuilder>::Builder:
                          octseq::builder::EmptyBuilder
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
            Unknown(UnknownRecordData<O>),
        }

        impl<Octets: AsRef<[u8]>, Name: ToName> ZoneRecordData<Octets, Name> {
            /// Scans a value of the given rtype.
            ///
            /// If the record data is given via the notation for unknown
            /// record types, the returned value will be of the
            /// `ZoneRecordData::Unknown(_)` variant.
            pub fn scan<S>(
                rtype: Rtype,
                scanner: &mut S
            ) -> Result<Self, S::Error>
            where
                S: $crate::base::scan::Scanner<Octets = Octets, Name = Name>
            {
                if scanner.scan_opt_unknown_marker()? {
                    UnknownRecordData::scan_without_marker(
                        rtype, scanner
                    ).map(ZoneRecordData::Unknown)
                }
                else {
                    match rtype {
                        $( $( $(
                            $mtype::RTYPE => {
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

        impl<O, N> ZoneRecordData<O, N> {
            fn rtype(&self) -> Rtype {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            inner.rtype()
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => inner.rtype(),
                }
            }
        }

        //--- OctetsFrom

        impl<Octs, SrcOcts, Name, SrcName>
            OctetsFrom<
                ZoneRecordData<SrcOcts, SrcName>
            >
            for ZoneRecordData<Octs, Name>
        where
            Octs: OctetsFrom<SrcOcts>,
            Name: OctetsFrom<
                SrcName, Error = Octs::Error
            >,
        {
            type Error = Octs::Error;

            fn try_octets_from(
                source: ZoneRecordData<SrcOcts, SrcName>
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
                            UnknownRecordData::try_octets_from(inner)?
                        ))
                    }
                }
            }
        }

        //--- FlattenInto

        impl<Octs, TargetOcts, Name, TargetName>
            FlattenInto<
                ZoneRecordData<TargetOcts, TargetName>
            >
            for ZoneRecordData<Octs, Name>
        where
            TargetOcts: OctetsFrom<Octs>,
            Name: FlattenInto<TargetName, AppendError = TargetOcts::Error>,
        {
            type AppendError = TargetOcts::Error;

            fn try_flatten_into(
                self
            ) -> Result<
                ZoneRecordData<TargetOcts, TargetName>,
                Self::AppendError
            > {
                match self {
                    $( $( $(
                        ZoneRecordData::$mtype(inner) => {
                            inner.flatten().map(
                                ZoneRecordData::$mtype
                            )
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(inner) => {
                        Ok(ZoneRecordData::Unknown(
                            UnknownRecordData::try_octets_from(inner)?
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

        impl<O, N> From<UnknownRecordData<O>>
        for ZoneRecordData<O, N> {
            fn from(value: UnknownRecordData<O>) -> Self {
                ZoneRecordData::Unknown(value)
            }
        }


        //--- PartialEq and Eq

        impl<O, OO, N, NN> PartialEq<ZoneRecordData<OO, NN>>
        for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: ToName, NN: ToName,
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
        where O: AsRef<[u8]>, N: ToName { }


        //--- PartialOrd, Ord, and CanonicalOrd

	impl<O, N> Ord for ZoneRecordData<O, N>
	where
		O: AsRef<[u8]>,
		N: ToName,
	{
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                match (self, other) {
                    $( $( $(
                        (
                            &ZoneRecordData::$mtype(ref self_inner),
                            &ZoneRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.cmp(other_inner)
                        }
                    )* )* )*
                    (
                        &ZoneRecordData::Unknown(ref self_inner),
                        &ZoneRecordData::Unknown(ref other_inner)
                    ) => {
                        self_inner.cmp(other_inner)
                    }
                    _ => self.rtype().cmp(&other.rtype())
                }
            }
	}

        impl<O, OO, N, NN> PartialOrd<ZoneRecordData<OO, NN>>
        for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: ToName, NN: ToName,
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
        CanonicalOrd<ZoneRecordData<OO, NN>>
        for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: CanonicalOrd<NN> + ToName,
            NN: ToName,
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

        impl<O, N> hash::Hash for ZoneRecordData<O, N>
        where O: AsRef<[u8]>, N: hash::Hash {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            $mtype::RTYPE.hash(state);
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

        impl<O, N> RecordData for ZoneRecordData<O, N> {
            fn rtype(&self) -> Rtype {
                ZoneRecordData::rtype(self)
            }
        }

        impl<'a, Octs: Octets + ?Sized>
        ParseRecordData<'a, Octs>
        for ZoneRecordData<Octs::Range<'a>, ParsedName<Octs::Range<'a>>> {
            fn parse_rdata(
                rtype: Rtype,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                match rtype {
                    $( $( $(
                        $mtype::RTYPE => {
                            Ok(Some(ZoneRecordData::$mtype(
                                $mtype::parse(parser)?
                            )))
                        }
                    )* )* )*
                    _ => {
                        Ok(UnknownRecordData::parse_rdata(
                            rtype, parser
                        )?.map(ZoneRecordData::Unknown))
                    }
                }
            }
        }

        impl<Octs, Name> ComposeRecordData for ZoneRecordData<Octs, Name>
        where Octs: AsRef<[u8]>, Name: ToName {
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


        //--- Display

        impl<O, N> fmt::Display for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>,
            N: fmt::Display
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

        impl<O, N> fmt::Debug for ZoneRecordData<O, N>
        where
            O: AsRef<[u8]>,
            N: fmt::Debug
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

        ///--- Present

        impl<O, N> $crate::zonefile::present::Present for ZoneRecordData<O, N>
        where
        O: AsRef<[u8]>,
        N: fmt::Display
        {
            fn present(&self, f: &mut $crate::zonefile::present::ZoneFileFormatter) -> fmt::Result {
                match *self {
                    $( $( $(
                        ZoneRecordData::$mtype(ref inner) => {
                            inner.present(f)
                        }
                    )* )* )*
                    ZoneRecordData::Unknown(ref inner) => inner.present(f),
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
            Opt(Opt<O>),
            Unknown(UnknownRecordData<O>),
        }

        impl<O, N> AllRecordData<O, N> {
            fn rtype(&self) -> Rtype {
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

                    AllRecordData::Opt(_) => Rtype::OPT,
                    AllRecordData::Unknown(ref inner) => inner.rtype(),
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

        impl<O, N> From<Opt<O>> for AllRecordData<O, N> {
            fn from(value: Opt<O>) -> Self {
                AllRecordData::Opt(value)
            }
        }

        impl<O, N> From<UnknownRecordData<O>>
        for AllRecordData<O, N> {
            fn from(
                value: UnknownRecordData<O>
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

        impl<Octs, SrcOcts, Name, SrcName>
            OctetsFrom<
                AllRecordData<SrcOcts, SrcName>
            >
            for AllRecordData<Octs, Name>
        where
            Octs: octseq::octets::OctetsFrom<SrcOcts>,
            Name: octseq::octets::OctetsFrom<
                SrcName, Error = Octs::Error,
            >,
        {
            type Error = Octs::Error;

            fn try_octets_from(
                source: AllRecordData<SrcOcts, SrcName>
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
                            Opt::try_octets_from(inner)?
                        ))
                    }
                    AllRecordData::Unknown(inner) => {
                        Ok(AllRecordData::Unknown(
                            UnknownRecordData::try_octets_from(inner)?
                        ))
                    }
                }
            }
        }

        //--- FlattenInto

        impl<Octs, TargetOcts, Name, TargetName>
            FlattenInto<
                AllRecordData<TargetOcts, TargetName>
            >
            for AllRecordData<Octs, Name>
        where
            TargetOcts: OctetsFrom<Octs>,
            Name: FlattenInto<TargetName, AppendError = TargetOcts::Error>,
        {
            type AppendError = TargetOcts::Error;

            fn try_flatten_into(
                self
            ) -> Result<
                AllRecordData<TargetOcts, TargetName>,
                Self::AppendError
            > {
                match self {
                    $( $( $(
                        AllRecordData::$mtype(inner) => {
                            inner.flatten().map(
                                AllRecordData::$mtype
                            )
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(inner) => {
                            inner.flatten().map(
                                AllRecordData::$ptype
                            )
                        }
                    )* )* )*
                    AllRecordData::Opt(inner) => {
                        Ok(AllRecordData::Opt(
                            Opt::try_octets_from(inner)?
                        ))
                    }
                    AllRecordData::Unknown(inner) => {
                        Ok(AllRecordData::Unknown(
                            UnknownRecordData::try_octets_from(inner)?
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
            N: ToName, NN: ToName
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
        where O: AsRef<[u8]>, N: ToName { }

        //--- PartialOrd, Ord, and CanonicalOrd

        impl<O, N> Ord for AllRecordData<O, N>
        where
            O: AsRef<[u8]>,
            N: ToName,
        {
            fn cmp(
                &self,
                other: &Self
            ) -> core::cmp::Ordering {
                match (self, other) {
                    $( $( $(
                        (
                            &AllRecordData::$mtype(ref self_inner),
                            &AllRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.cmp(other_inner)
                        }
                    )* )* )*
                    $( $( $(
                        (
                            &AllRecordData::$ptype(ref self_inner),
                            &AllRecordData::$ptype(ref other_inner)
                        )
                        => {
                            self_inner.cmp(other_inner)
                        }
                    )* )* )*
                    (
                        &AllRecordData::Opt(ref self_inner),
                        &AllRecordData::Opt(ref other_inner)
                    ) => {
                        self_inner.cmp(other_inner)
                    }
                    (
                        &AllRecordData::Unknown(ref self_inner),
                        &AllRecordData::Unknown(ref other_inner)
                    ) => {
                        self_inner.cmp(other_inner)
                    }
                    _ => self.rtype().cmp(&other.rtype())
                }
            }
        }

        impl<O, OO, N, NN> PartialOrd<AllRecordData<OO, NN>>
        for AllRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: ToName, NN: ToName,
        {
            fn partial_cmp(
                &self,
                other: &AllRecordData<OO, NN>
            ) -> Option<core::cmp::Ordering> {
                match (self, other) {
                    $( $( $(
                        (
                            &AllRecordData::$mtype(ref self_inner),
                            &AllRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.partial_cmp(other_inner)
                        }
                    )* )* )*
                    $( $( $(
                        (
                            &AllRecordData::$ptype(ref self_inner),
                            &AllRecordData::$ptype(ref other_inner)
                        )
                        => {
                            self_inner.partial_cmp(other_inner)
                        }
                    )* )* )*
                    (
                        &AllRecordData::Opt(ref self_inner),
                        &AllRecordData::Opt(ref other_inner)
                    ) => {
                        self_inner.partial_cmp(other_inner)
                    }
                    (
                        &AllRecordData::Unknown(ref self_inner),
                        &AllRecordData::Unknown(ref other_inner)
                    ) => {
                        self_inner.partial_cmp(other_inner)
                    }
                    _ => self.rtype().partial_cmp(&other.rtype())
                }
            }
        }

        impl<O, OO, N, NN>
        CanonicalOrd<AllRecordData<OO, NN>>
        for AllRecordData<O, N>
        where
            O: AsRef<[u8]>, OO: AsRef<[u8]>,
            N: CanonicalOrd<NN> + ToName,
            NN: ToName,
        {
            fn canonical_cmp(
                &self,
                other: &AllRecordData<OO, NN>
            ) -> core::cmp::Ordering {
                match (self, other) {
                    $( $( $(
                        (
                            &AllRecordData::$mtype(ref self_inner),
                            &AllRecordData::$mtype(ref other_inner)
                        )
                        => {
                            self_inner.canonical_cmp(other_inner)
                        }
                    )* )* )*
                    $( $( $(
                        (
                            &AllRecordData::$ptype(ref self_inner),
                            &AllRecordData::$ptype(ref other_inner)
                        )
                        => {
                            self_inner.canonical_cmp(other_inner)
                        }
                    )* )* )*
                    (
                        &AllRecordData::Opt(ref self_inner),
                        &AllRecordData::Opt(ref other_inner)
                    ) => {
                        self_inner.canonical_cmp(other_inner)
                    }
                    (
                        &AllRecordData::Unknown(ref self_inner),
                        &AllRecordData::Unknown(ref other_inner)
                    ) => {
                        self_inner.canonical_cmp(other_inner)
                    }
                    _ => self.rtype().cmp(&other.rtype())
                }
            }
        }


        //--- Hash

        impl<O, N> hash::Hash for AllRecordData<O, N>
        where O: AsRef<[u8]>, N: hash::Hash {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
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

        impl<O, N> RecordData for AllRecordData<O, N> {
            fn rtype(&self) -> Rtype {
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

        impl<'a, Octs: Octets + ?Sized>
        ParseAnyRecordData<'a, Octs>
        for AllRecordData<Octs::Range<'a>, ParsedName<Octs::Range<'a>>> {
            fn parse_any_rdata(
                rtype: Rtype,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Self, ParseError> {
                match rtype {
                    $( $( $(
                        $mtype::RTYPE => {
                            Ok(AllRecordData::$mtype(
                                $mtype::parse(parser)?
                            ))
                        }
                    )* )* )*
                    $( $( $(
                        $ptype::RTYPE => {
                            Ok(AllRecordData::$ptype(
                                $ptype::parse(parser)?
                            ))
                        }
                    )* )* )*
                    Opt::RTYPE => {
                        Ok(AllRecordData::Opt(
                            Opt::parse(parser)?
                        ))
                    }
                    _ => {
                        Ok(AllRecordData::Unknown(
                            UnknownRecordData::parse_any_rdata(
                                rtype, parser
                            )?
                        ))
                    }
                }
            }
        }

        impl<'a, Octs: Octets + ?Sized>
        ParseRecordData<'a, Octs>
        for AllRecordData<Octs::Range<'a>, ParsedName<Octs::Range<'a>>> {
            fn parse_rdata(
                rtype: Rtype,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                ParseAnyRecordData::parse_any_rdata(rtype, parser).map(Some)
            }
        }

        impl<Octs, Name> ComposeRecordData for AllRecordData<Octs, Name>
        where Octs: AsRef<[u8]>, Name: ToName {
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

        impl<O, N> fmt::Display for AllRecordData<O, N>
        where O: Octets, N: fmt::Display {
            fn fmt(
                &self, f: &mut fmt::Formatter
            ) -> fmt::Result {
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

        impl<O, N> fmt::Debug for AllRecordData<O, N>
        where O: Octets, N: fmt::Debug {
            fn fmt(
                &self, f: &mut fmt::Formatter
            ) -> fmt::Result {
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
                            fmt::Debug::fmt(inner, f)?;
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
                            fmt::Debug::fmt(inner, f)?;
                            f.write_str(")")
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => {
                        f.write_str("AllRecordData::Opt(")?;
                        fmt::Debug::fmt(inner, f)?;
                        f.write_str(")")
                    }
                    AllRecordData::Unknown(ref inner) => {
                        f.write_str("AllRecordData::Unknown(")?;
                        fmt::Debug::fmt(inner, f)?;
                        f.write_str(")")
                    }
                }
            }
        }

        //--- Present
        impl<O, N> $crate::zonefile::present::Present for AllRecordData<O, N>
        where O: Octets, N: fmt::Display {
            fn present(
                &self, f: &mut $crate::zonefile::present::ZoneFileFormatter
            ) -> fmt::Result {
                match *self {
                    $( $( $(
                        AllRecordData::$mtype(ref inner) => {
                            inner.present(f)
                        }
                    )* )* )*
                    $( $( $(
                        AllRecordData::$ptype(ref inner) => {
                            inner.present(f)
                        }
                    )* )* )*
                    AllRecordData::Opt(ref inner) => inner.present(f),
                    AllRecordData::Unknown(ref inner) => inner.present(f),
                }
            }
        }
    }
}

//------------ name_type! --------------------------------------------------

/// A macro for implementing a record data type with a single domain name.
///
/// Implements some basic methods plus the `RecordData`, `FlatRecordData`,
/// and `Display` traits.
macro_rules! name_type_base {
    ($(#[$attr:meta])* (
        $target:ident, $rtype:ident, $field:ident, $into_field:ident
    ) ) => {
        $(#[$attr])*
        #[derive(Clone, Debug)]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize)
        )]
        pub struct $target<N: ?Sized> {
            $field: N
        }

        impl $target<()> {
            /// The rtype of this record data type.
            pub(crate) const RTYPE: $crate::base::iana::Rtype
                = $crate::base::iana::Rtype::$rtype;
        }

        impl<N> $target<N> {
            pub fn new($field: N) -> Self {
                $target { $field }
            }

            pub fn $field(&self) -> &N {
                &self.$field
            }

            pub fn $into_field(self) -> N {
                self.$field
            }

            pub fn scan<S: crate::base::scan::Scanner<Name = N>>(
                scanner: &mut S
            ) -> Result<Self, S::Error> {
                scanner.scan_name().map(Self::new)
            }

            pub(in crate::rdata) fn convert_octets<Target: OctetsFrom<N>>(
                self
            ) -> Result<$target<Target>, Target::Error> {
                Target::try_octets_from(self.$field).map($target::new)
            }

            pub(in crate::rdata) fn flatten<Target>(
                self
            ) -> Result<$target<Target>, N::AppendError>
            where
                N: crate::base::name::FlattenInto<Target>
            {
                self.$field.try_flatten_into().map($target::new)
            }
        }

        impl<Octs: Octets> $target<ParsedName<Octs>> {
            pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
                parser: &mut Parser<'a, Src>,
            ) -> Result<Self, ParseError> {
                ParsedName::parse(parser).map(Self::new)
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

        //--- FlattenInto

        impl<Name, Target> crate::base::name::FlattenInto<$target<Target>>
        for $target<Name>
        where Name: crate::base::name::FlattenInto<Target> {
            type AppendError = Name::AppendError;

            fn try_flatten_into(
                self
            ) -> Result<$target<Target>, Self::AppendError> {
                self.$field.try_flatten_into().map($target::new)
            }
        }

        //--- PartialEq and Eq

        impl<N, NN> PartialEq<$target<NN>> for $target<N>
        where N: ToName, NN: ToName {
            fn eq(&self, other: &$target<NN>) -> bool {
                self.$field.name_eq(&other.$field)
            }
        }

        impl<N: ToName> Eq for $target<N> { }


        //--- PartialOrd and Ord
        //
        // For CanonicalOrd, see below.

        impl<N, NN> PartialOrd<$target<NN>> for $target<N>
        where N: ToName, NN: ToName {
            fn partial_cmp(&self, other: &$target<NN>) -> Option<Ordering> {
                Some(self.$field.name_cmp(&other.$field))
            }
        }

        impl<N: ToName> Ord for $target<N> {
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

        //--- RecordData, ParseRecordData

        impl<N> $crate::base::rdata::RecordData for $target<N> {
            fn rtype(&self) -> $crate::base::iana::Rtype {
                $target::RTYPE
            }
        }

        impl<'a, Octs> $crate::base::rdata::ParseRecordData<'a, Octs>
        for $target<$crate::base::name::ParsedName<Octs::Range<'a>>>
        where Octs: octseq::octets::Octets + ?Sized {
            fn parse_rdata(
                rtype: $crate::base::iana::Rtype,
                parser: &mut octseq::parse::Parser<'a, Octs>,
            ) -> Result<Option<Self>, $crate::base::wire::ParseError> {
                if rtype == $target::RTYPE {
                    Self::parse(parser).map(Some)
                }
                else {
                    Ok(None)
                }
            }
        }

        //--- Display

        impl<N: fmt::Display> fmt::Display for $target<N> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}.", self.$field)
            }
        }

        //--- Present

        impl<N: fmt::Display> $crate::zonefile::present::Present for $target<N> {
            fn present(&self, f: &mut $crate::zonefile::present::ZoneFileFormatter) -> fmt::Result {
                use std::fmt::Write;
                write!(f, "{}.", self.$field)
            }
        }
    }
}

macro_rules! name_type_well_known {
    ($(#[$attr:meta])* (
        $target:ident, $rtype:ident, $field:ident, $into_field:ident
    ) ) => {
        name_type_base! {
            $( #[$attr] )*
            ($target, $rtype, $field, $into_field)
        }

        impl<N: ToName> $crate::base::rdata::ComposeRecordData
        for $target<N> {
            fn rdlen(&self, compress: bool) -> Option<u16> {
                if compress {
                    None
                }
                else {
                    Some(self.$field.compose_len())
                }
            }

            fn compose_rdata<Target: $crate::base::wire::Composer + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                if target.can_compress() {
                    target.append_compressed_name(&self.$field)
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

        impl<N: ToName, NN: ToName> CanonicalOrd<$target<NN>> for $target<N> {
            fn canonical_cmp(&self, other: &$target<NN>) -> Ordering {
                self.$field.lowercase_composed_cmp(&other.$field)
            }
        }
    }
}

macro_rules! name_type_canonical {
    ($(#[$attr:meta])* (
        $target:ident, $rtype:ident, $field:ident, $into_field:ident
    ) ) => {
        name_type_base! {
            $( #[$attr] )*
            ($target, $rtype, $field, $into_field)
        }

        impl<N: ToName> $crate::base::rdata::ComposeRecordData
        for $target<N> {
            fn rdlen(&self, _compress: bool) -> Option<u16> {
                Some(self.$field.compose_len())
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

        impl<N: ToName, NN: ToName> CanonicalOrd<$target<NN>> for $target<N> {
            fn canonical_cmp(&self, other: &$target<NN>) -> Ordering {
                self.$field.lowercase_composed_cmp(&other.$field)
            }
        }
    }
}

#[allow(unused_macros)]
macro_rules! name_type {
    ($(#[$attr:meta])* (
        $target:ident, $rtype:ident, $field:ident, $into_field:ident
    ) ) => {
        name_type_base! {
            $( #[$attr] )*
            ($target, $rtype, $field, $into_field)
        }

        impl<N: ToName> $crate::base::rdata::ComposeRecordData
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

        impl<N: ToName, NN: ToName> CanonicalOrd<$target<NN>> for $target<N> {
            fn canonical_cmp(&self, other: &$target<NN>) -> Ordering {
                self.$field.name_cmp(&other.$field)
            }
        }
    }
}
