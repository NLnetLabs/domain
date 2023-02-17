use super::{
    ComposeSvcbValue, LongSvcbValue, ParseSvcbValue, SvcbValue,
    UnknownSvcbValue,
};
use crate::base::iana::SvcbParamKey;
use crate::base::net::{Ipv4Addr, Ipv6Addr};
use crate::base::wire::{Compose, Parse, ParseError};
use crate::utils::base64;
use octseq::builder::{
    EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder, ShortBuf
};
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
use octseq::str::Str;
use core::{fmt, hash, str};
use core::fmt::Write as _;
use core::str::FromStr;

//------------ AllValues -----------------------------------------------------

macro_rules! values_enum {
    (
        $( $type:ident $( < $( $type_arg:ident ),* > )?, )+
    ) => {
        #[derive(Debug, Clone)]
        pub enum AllValues<Octs> {
            $(
                $type($type $( < $( $type_arg ),* > )? ),
            )+
            Unknown(UnknownSvcbValue<Octs>),
        }

        impl<Octs: AsRef<[u8]>> AllValues<Octs> {
            /// Parses any SVCB value.
            ///
            /// If a known variant fails to parse, returns it as the unknown
            /// variant instead.
            ///
            /// # Panics
            ///
            /// Panics if taking the remaining octets from the parser fails.
            pub(super) fn parse_any<'a, Src>(
                key: SvcbParamKey,
                parser: &mut Parser<'a, Src>,
            ) -> Self
            where Src: Octets<Range<'a> = Octs> + ?Sized {
                let pos = parser.pos();
                let res = match key {
                    $(
                        SvcbParamKey::$type => {
                            $type::parse(
                                parser
                            ).map(Self::$type)
                        }
                    )+
                    _ => {
                        UnknownSvcbValue::parse(
                            key, parser
                        ).map(Self::Unknown)
                    }
                };
                if let Ok(res) = res {
                    return res
                }
                parser.seek(pos).expect("invalid SvcbParams");
                let octets = parser.parse_octets(
                    parser.remaining()
                ).expect("invalid SvcbParams");

                Self::Unknown(unsafe { 
                    UnknownSvcbValue::new_unchecked(key, octets)
                })
            }
        }

        //--- From

        $(
            impl<Octs> From<$type $( < $( $type_arg ),* > )*>
            for AllValues<Octs> {
                fn from(p: $type $( < $( $type_arg ),* > )*) -> Self {
                    Self::$type(p)
                }
            }
        )+

        impl<Octs> From<UnknownSvcbValue<Octs>> for AllValues<Octs> {
            fn from(p: UnknownSvcbValue<Octs>) -> Self {
                Self::Unknown(p)
            }
        }

        //--- SvcbValue et al.

        impl<Octs> SvcbValue for AllValues<Octs> {
            fn key(&self) -> SvcbParamKey {
                match self {
                    $(
                        Self::$type(v) => v.key(),
                    )+
                    Self::Unknown(v) => v.key(),
                }
            }
        }

        impl<'a, Octs> ParseSvcbValue<'a, Octs> for AllValues<Octs::Range<'a>>
        where Octs: Octets + ?Sized {
            fn parse_value(
                key: SvcbParamKey,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                match key {
                    $(
                        SvcbParamKey::$type => {
                            $type::parse(
                                parser
                            ).map(|res| Some(Self::$type(res)))
                        }
                    )+
                    _ => {
                        UnknownSvcbValue::parse_value(
                            key, parser
                        ).map(|res| res.map(Self::Unknown))
                    }
                }
            }
        }

        impl<Octs: AsRef<[u8]>> ComposeSvcbValue for AllValues<Octs> {
            fn compose_len(&self) -> u16 {
                match self {
                    $(
                        Self::$type(v) => v.compose_len(),
                    )*
                    Self::Unknown(v) => v.compose_len(),
                }
            }

            fn compose_value<Target: OctetsBuilder + ?Sized>(
                &self, target: &mut Target,
            ) -> Result<(), Target::AppendError> {
                match self {
                    $(
                        Self::$type(v) => v.compose_value(target),
                    )*
                    Self::Unknown(v) => v.compose_value(target),
                }
            }
        }

        //--- PartialEq and Eq
        
        impl<Octs, OtherOcts> PartialEq<AllValues<OtherOcts>>
        for AllValues<Octs>
        where
            Octs: AsRef<[u8]>,
            OtherOcts: AsRef<[u8]>,
        {
            fn eq(&self, other: &AllValues<OtherOcts>) -> bool {
                match (self, other) {
                    $(
                        (AllValues::$type(left), AllValues::$type(right)) => {
                            left.eq(right)
                        }
                    )*
                    (AllValues::Unknown(left), AllValues::Unknown(right)) => {
                        left.eq(right)
                    }
                    _ => false
                }
            }
        }

        impl<Octs: AsRef<[u8]>> Eq for AllValues<Octs> { }

        //--- Hash

        impl<Octs: AsRef<[u8]>> hash::Hash for AllValues<Octs> {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                match self {
                    $(
                        Self::$type(value) => value.hash(state),
                    )*
                    Self::Unknown(value) => value.hash(state)
                }
            }
        }

        //--- Display and Debug

        impl<Octs: Octets> fmt::Display for AllValues<Octs> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self {
                    $(
                        Self::$type(v) => v.fmt(f),
                    )*
                    Self::Unknown(v) => v.fmt(f),
                }
            }
        }
    }
}

values_enum! {
    Mandatory<Octs>,
    Alpn<Octs>,
    NoDefaultAlpn,
    Port,
    Ech<Octs>,
    Ipv4Hint<Octs>,
    Ipv6Hint<Octs>,
    DohPath<Octs>,
}

//------------ octets_wrapper ------------------------------------------------

/// Defines the standard methods for a parameter type wrapping octets.
macro_rules! octets_wrapper {
    ($name:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name<Octs: ?Sized>(Octs);

        impl<Octs> $name<Octs> {
            /// Creates a new value from octets without checking.
            ///
            /// # Safety
            ///
            /// The caller has to ensure that `octets` contains a properly
            /// formated value of at most 65,535 octets.
            pub unsafe fn from_octets_unchecked(octets: Octs) -> Self {
                $name(octets)
            }
        }

        impl $name<[u8]> {
            /// Creates a new value for a slice without checking.
            ///
            /// # Safety
            ///
            /// The caller has to ensure that `slice` contains a properly
            /// formated value of at most 65,535 octets.
            pub unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
                &*(slice as *const [u8] as *const Self)
            }
        }

        impl<Octs: ?Sized> $name<Octs> {
            pub fn as_octets(&self) -> &Octs {
                &self.0
            }

            pub fn as_slice(&self) -> &[u8]
            where Octs: AsRef<[u8]> {
                self.0.as_ref()
            }
        }

        //--- OctetsFrom

        impl<O, OO> OctetsFrom<$name<O>> for $name<OO>
        where
            OO: OctetsFrom<O>,
        {
            type Error = OO::Error;

            fn try_octets_from(
                source: $name<O>,
            ) -> Result<Self, Self::Error> {
                Ok(unsafe {
                    $name::from_octets_unchecked(
                        OO::try_octets_from(source.0)?
                    )
                })
            }
        }

        //--- AsRef

        impl<Octs> AsRef<Octs> for $name<Octs> {
            fn as_ref(&self) -> &Octs {
                self.as_octets()
            }
        }

        impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for $name<Octs> {
            fn as_ref(&self) -> &[u8] {
                self.as_slice()
            }
        }

        //--- PartialEq and Eq

        impl<Octs, OtherOcts> PartialEq<$name<OtherOcts>> for $name<Octs>
        where
            Octs: AsRef<[u8]>,
            OtherOcts: AsRef<[u8]>,
        {
            fn eq(&self, other: &$name<OtherOcts>) -> bool {
                self.as_slice().eq(other.as_slice())
            }
        }

        impl<Octs: AsRef<[u8]>> Eq for $name<Octs> { }

        //--- Hash

        impl<Octs: AsRef<[u8]>> hash::Hash for $name<Octs> {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                self.as_slice().hash(state)
            }
        }

        //--- SvcbValue et al.

        impl<Octs: ?Sized> SvcbValue for $name<Octs> {
            fn key(&self) -> SvcbParamKey {
                SvcbParamKey::$name
            }
        }

        impl<'a, Octs> ParseSvcbValue<'a, Octs> for $name<Octs::Range<'a>>
        where Octs: Octets + ?Sized {
            fn parse_value(
                key: SvcbParamKey,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                if key == SvcbParamKey::$name {
                    Self::parse(parser).map(Some)
                }
                else {
                    Ok(None)
                }
            }
        }

        impl<Octs: AsRef<[u8]> + ?Sized> ComposeSvcbValue for $name<Octs> {
            fn compose_len(&self) -> u16 {
                u16::try_from(self.as_slice().len()).expect("long value")
            }

            fn compose_value<Target: OctetsBuilder + ?Sized>(
                &self, target: &mut Target,
            ) -> Result<(), Target::AppendError> {
                target.append_slice(self.as_slice())
            }
        }
    };

    ($name:ident, $iter:ident) => {
        octets_wrapper!($name);

        impl<Octs: AsRef<[u8]> + ?Sized> $name<Octs> {
            /// Iterate over the internal items.
            pub fn iter(&self) -> $iter<'_, Octs> {
                $iter {
                    parser: Parser::from_ref(&self.0),
                }
            }
        }

        /// An iterator type to parse the internal items.
        pub struct $iter<'a, Octs: ?Sized> {
            parser: Parser<'a, Octs>,
        }
    };
}

//------------ Mandatory -----------------------------------------------------

octets_wrapper!(Mandatory, MandatoryIter);

impl<Octs: AsRef<[u8]>> Mandatory<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Mandatory::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a new value from a list of keys.
    ///
    /// The created value will contain all the keys returned by the iterator
    /// in the order provided. The function does not check for duplicates.
    ///
    /// Returns an error if the octets builder runs out of space or the
    /// resulting value would be longer than 65,535 octets.
    pub fn from_keys(
        keys: impl Iterator<Item = SvcbParamKey>
    ) -> Result<Self, BuildValueError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
    {
        let mut octets = EmptyBuilder::empty();
        for item in keys {
            item.compose(&mut octets)?;
        }
        let octets = Octs::from_builder(octets);
        if LongSvcbValue::check_len(octets.as_ref().len()).is_err() {
            return Err(BuildValueError::LongSvcbValue)
        }
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Mandatory<[u8]> {
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongSvcbValue::check_len(slice.len())?;
        if slice.len() % usize::from(SvcbParamKey::COMPOSE_LEN) != 0 {
            return Err(ParseError::form_error("invalid mandatory parameter"))
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Mandatory<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

impl<'a, Octs: Octets + ?Sized> Iterator for MandatoryIter<'a, Octs> {
    type Item = SvcbParamKey;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(
            SvcbParamKey::parse(
                &mut self.parser
            ).expect("invalid mandatory parameter")
        )
    }
}

impl<Octs: Octets + ?Sized> fmt::Display for Mandatory<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, v) in self.iter().enumerate() {
            if i == 0 {
                write!(f, "mandatory={}", v)?;
            } else {
                write!(f, ",{}", v)?;
            }
        }
        Ok(())
    }
}


//------------ Alpn ----------------------------------------------------------

octets_wrapper!(Alpn, AlpnIter);

impl<Octs: AsRef<[u8]>> Alpn<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Alpn::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Alpn<[u8]> {
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongSvcbValue::check_len(slice.len())?;
        let mut parser = Parser::from_ref(slice);
        while parser.remaining() > 0 {
            let len = usize::from(u8::parse(&mut parser)?);
            parser.advance(len)?;
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Alpn<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

impl<'a, Octs: Octets + ?Sized> Iterator for AlpnIter<'a, Octs> {
    type Item = Octs::Range<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None
        }
        let len = usize::from(
            u8::parse(&mut self.parser).expect("invalid alpn parameter")
        );
        Some(self.parser.parse_octets(len).expect("invalid alpn parameter"))
    }
}

impl<Octs: Octets + ?Sized> fmt::Display for Alpn<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, v) in self.iter().enumerate() {
            if i == 0 {
                f.write_str("alpn=")?;
            } else {
                f.write_str(",")?;
            }
            for ch in v.as_ref() {
                f.write_char(*ch as char)?;
            }
        }
        Ok(())
    }
}

//------------ AlpnBuilder ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct AlpnBuilder<Target> {
    target: Target,
}

impl<Target> AlpnBuilder<Target> {
    pub fn empty() -> Self
    where
        Target: EmptyBuilder,
    {
        AlpnBuilder { target: Target::empty() }
    }

    pub fn push(
        &mut self, protocol: impl AsRef<[u8]>
    ) -> Result<(), AlpnPushError>
    where Target: OctetsBuilder + AsRef<[u8]> {
        let protocol = protocol.as_ref();
        if protocol.is_empty() {
            return Err(AlpnPushError::InvalidProtocol)
        }
        let len = u8::try_from(
            protocol.len()
        ).map_err(|_| AlpnPushError::InvalidProtocol)?;
        LongSvcbValue::check_len(
            self.target.as_ref().len().checked_add(
                protocol.len() + 1
            ).expect("long Alpn value")
        ).map_err(|_| AlpnPushError::LongSvcbValue)?;
        len.compose(&mut self.target).map(Into::into)?;
        self.target.append_slice(
            protocol
        ).map_err(|_| AlpnPushError::ShortBuf)
    }

    pub fn freeze(self) -> Alpn<Target::Octets>
    where
        Target: FreezeBuilder
    {
        unsafe { Alpn::from_octets_unchecked(self.target.freeze()) }
    }
}

//------------ NoDefaultAlpn -------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NoDefaultAlpn;

impl NoDefaultAlpn {
    pub fn parse<Src: Octets + ?Sized>(
        _parser: &mut Parser<Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self)
    }
}

//--- SvcbValue et al.

impl SvcbValue for NoDefaultAlpn {
    fn key(&self) -> SvcbParamKey {
        SvcbParamKey::NoDefaultAlpn
    }
}

impl<'a, Octs: Octets + ?Sized> ParseSvcbValue<'a, Octs> for NoDefaultAlpn {
    fn parse_value(
        key: SvcbParamKey,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if key == SvcbParamKey::NoDefaultAlpn {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeSvcbValue for NoDefaultAlpn {
    fn compose_len(&self) -> u16 {
        0
    }

    fn compose_value<Target: OctetsBuilder + ?Sized>(
        &self, _target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        Ok(())
    }
}

//--- Display

impl fmt::Display for NoDefaultAlpn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("nodefaultalpn")
    }
}

//------------ Port ----------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Port(u16);

impl Port {
    pub fn new(port: u16) -> Self {
        Port(port)
    }

    pub fn parse<Src: Octets + ?Sized>(
        parser: &mut Parser<Src>,
    ) -> Result<Self, ParseError> {
        u16::parse(parser).map(Port::new)
    }

    pub fn port(self) -> u16 {
        self.0
    }
}

//--- SvcbValue et al.

impl SvcbValue for Port {
    fn key(&self) -> SvcbParamKey {
        SvcbParamKey::Port
    }
}

impl<'a, Octs: Octets + ?Sized> ParseSvcbValue<'a, Octs> for Port {
    fn parse_value(
        key: SvcbParamKey,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if key == SvcbParamKey::Port {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeSvcbValue for Port {
    fn compose_len(&self) -> u16 {
        u16::COMPOSE_LEN 
    }

    fn compose_value<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.0.compose(target)
    }
}

//--- Display

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "port={}", self.0)
    }
}

//------------ Ech -----------------------------------------------------------

octets_wrapper!(Ech);

impl<Octs: AsRef<[u8]>> Ech<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, LongSvcbValue> {
        Ech::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Ech<[u8]> {
    pub fn from_slice(slice: &[u8]) -> Result<&Self, LongSvcbValue> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    fn check_slice(slice: &[u8]) -> Result<(), LongSvcbValue> {
        LongSvcbValue::check_len(slice.len())?;
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Ech<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(
            parser.parse_octets(parser.remaining())?
        ).map_err(Into::into)
    }
}

//--- Display

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for Ech<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.as_slice().is_empty() {
            f.write_str("ech")
        }
        else {
            f.write_str("ech=")?;
            base64::display(self.as_slice(), f)
        }
    }
}

//------------ Ipv4Hint ------------------------------------------------------

octets_wrapper!(Ipv4Hint, Ipv4HintIter);

impl<Octs: AsRef<[u8]>> Ipv4Hint<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Ipv4Hint::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    pub fn from_addrs(
        addrs: impl IntoIterator<Item = Ipv4Addr>
    ) -> Result<Self, BuildValueError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
    {
        let mut octets = EmptyBuilder::empty();
        for item in addrs {
            item.compose(&mut octets)?;
        }
        let octets = Octs::from_builder(octets);
        if LongSvcbValue::check_len(octets.as_ref().len()).is_err() {
            return Err(BuildValueError::LongSvcbValue)
        }
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Ipv4Hint<[u8]> {
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongSvcbValue::check_len(slice.len())?;
        if slice.len() % usize::from(Ipv4Addr::COMPOSE_LEN) != 0 {
            return Err(ParseError::form_error("invalid ipv4hint parameter"))
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Ipv4Hint<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

impl<'a, Octs: Octets + ?Sized> Iterator for Ipv4HintIter<'a, Octs> {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(
            Ipv4Addr::parse(
                &mut self.parser
            ).expect("invalid ipv4hint parameter")
        )
    }
}

impl<Octs: Octets + ?Sized> fmt::Display for Ipv4Hint<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, v) in self.iter().enumerate() {
            if i == 0 {
                write!(f, "ipv4hint={}", v)?;
            } else {
                write!(f, ",{}", v)?;
            }
        }
        Ok(())
    }
}

//------------ Ipv6Hint ------------------------------------------------------

octets_wrapper!(Ipv6Hint, Ipv6HintIter);

impl<Octs: AsRef<[u8]>> Ipv6Hint<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Ipv6Hint::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    pub fn from_addrs(
        addrs: impl IntoIterator<Item = Ipv6Addr>
    ) -> Result<Self, BuildValueError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
    {
        let mut octets = EmptyBuilder::empty();
        for item in addrs {
            item.compose(&mut octets)?;
        }
        let octets = Octs::from_builder(octets);
        if LongSvcbValue::check_len(octets.as_ref().len()).is_err() {
            return Err(BuildValueError::LongSvcbValue)
        }
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Ipv6Hint<[u8]> {
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongSvcbValue::check_len(slice.len())?;
        if slice.len() % usize::from(Ipv6Addr::COMPOSE_LEN) != 0 {
            return Err(ParseError::form_error("invalid ipv6hint parameter"))
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Ipv6Hint<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

//--- Iterator

impl<'a, Octs: Octets + ?Sized> Iterator for Ipv6HintIter<'a, Octs> {
    type Item = Ipv6Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(
            Ipv6Addr::parse(
                &mut self.parser
            ).expect("invalid ipv6hint parameter")
        )
    }
}

//--- Display

impl<Octs: Octets + ?Sized> fmt::Display for Ipv6Hint<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, v) in self.iter().enumerate() {
            if i == 0 {
                write!(f, "ipv6hint={}", v)?;
            } else {
                write!(f, ",{}", v)?;
            }
        }
        Ok(())
    }
}

//------------ DohPath -------------------------------------------------------
//
// https://datatracker.ietf.org/doc/html/draft-ietf-add-svcb-dns

octets_wrapper!(DohPath);

impl<Octs: AsRef<[u8]>> DohPath<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, LongSvcbValue> {
        DohPath::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl DohPath<[u8]> {
    pub fn from_slice(slice: &[u8]) -> Result<&Self, LongSvcbValue> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    fn check_slice(slice: &[u8]) -> Result<(), LongSvcbValue> {
        LongSvcbValue::check_len(slice.len())?;
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> DohPath<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(
            parser.parse_octets(parser.remaining())?
        ).map_err(Into::into)
    }
}

//--- TryFrom and FromStr

impl<Octs: AsRef<[u8]>> TryFrom<Str<Octs>> for DohPath<Octs> {
    type Error = LongSvcbValue;

    fn try_from(src: Str<Octs>) -> Result<Self, Self::Error> {
        Self::from_octets(src.into_octets())
    }
}

impl<Octs> FromStr for DohPath<Octs>
where
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder:
        EmptyBuilder
        + FreezeBuilder<Octets = Octs>
{
    type Err = BuildValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DohPath::check_slice(s.as_bytes())?;
        let mut res: <Octs as FromBuilder>::Builder = EmptyBuilder::empty();
        res.append_slice(s.as_bytes()).map_err(Into::into)?;
        Ok(unsafe { Self::from_octets_unchecked(res.freeze()) })
    }
}

//--- Display

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for DohPath<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.as_slice().is_empty() {
            f.write_str("dohpath")
        }
        else {
            f.write_str("dohpath=")?;
            let mut s = self.as_slice();

            // XXX Should this be moved to base::utils?
            while !s.is_empty() {
                match str::from_utf8(s) {
                    Ok(s) => return f.write_str(s),
                    Err(err) => {
                        let end = err.valid_up_to();
                        if end > 0 {
                            f.write_str(unsafe {
                                str::from_utf8_unchecked(&s[..end])
                            })?;
                        }
                        f.write_str("\u{FFFD}")?;
                        match err.error_len() {
                            Some(len) => {
                                s = &s[end + len..];
                            }
                            None => break,
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

//------------ BuildValueError -----------------------------------------------

/// An error happened while constructing an SVCB value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildValueError {
    /// The value would exceed the allow length of a value.
    LongSvcbValue,

    /// The underlying octets builder ran out of buffer space.
    ShortBuf,
}

impl From<LongSvcbValue> for BuildValueError {
    fn from(_: LongSvcbValue) -> Self {
        Self::LongSvcbValue
    }
}

impl<T: Into<ShortBuf>> From<T> for BuildValueError {
    fn from(_: T) -> Self {
        Self::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for BuildValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::LongSvcbValue => f.write_str("long SVCB value"),
            Self::ShortBuf => ShortBuf.fmt(f)
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildValueError {}

//------------ PushAlpnError -------------------------------------------------

/// An error happened while constructing an SVCB value.
#[derive(Clone, Copy, Debug)]
pub enum AlpnPushError {
    /// The protocol value is not valid.
    ///
    /// It was either empty or longer than 255 octets.
    InvalidProtocol,

    /// The value would exceed the allow length of a value.
    LongSvcbValue,

    /// The underlying octets builder ran out of buffer space.
    ShortBuf,
}

impl<T: Into<ShortBuf>> From<T> for AlpnPushError {
    fn from(_: T) -> Self {
        Self::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for AlpnPushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidProtocol => f.write_str("invalid ALPN protocol"),
            Self::LongSvcbValue => f.write_str("long SVCB value"),
            Self::ShortBuf => ShortBuf.fmt(f)
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AlpnPushError {}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vectors_alpn_escape() {
        let mut parser = Parser::from_ref(b"\
            \x08\
            \x66\x5c\x6f\x6f\x2c\x62\x61\x72\
            \x02\
            \x68\x32\
        ".as_ref());
        let alpn = Alpn::parse(&mut parser).unwrap();
        assert_eq!(parser.remaining(), 0);
        assert!(
            alpn.iter().eq(
                [
                    br#"f\oo,bar"#.as_ref(),
                    b"h2".as_ref(),
                ].into_iter()
            )
        );
    }

}

