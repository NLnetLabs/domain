use super::{
    ComposeSvcParamValue, LongSvcParam, ParseSvcParamValue, PushError,
    SvcParamValue, SvcParams, SvcParamsBuilder, UnknownSvcParam,
};
use crate::base::iana::SvcParamKey;
use crate::base::net::{Ipv4Addr, Ipv6Addr};
use crate::base::wire::{Compose, Parse, ParseError};
use crate::utils::base64;
use core::fmt::Write as _;
use core::str::FromStr;
use core::{fmt, hash, mem, str};
use octseq::builder::{
    EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder, ShortBuf,
};
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
use octseq::str::Str;

//============ AllValues =====================================================

macro_rules! values_enum {
    (
        $( $type:ident $( < $( $type_arg:ident ),* > )?, )+
    ) => {
        /// All known service bindings parameter values.
        ///
        /// This type allows parsing all known parameter values into their
        /// dedicated type and all unknown values into their raw form.
        #[derive(Debug, Clone)]
        pub enum AllValues<Octs> {
            $(
                $type($type $( < $( $type_arg ),* > )? ),
            )+
            Unknown(UnknownSvcParam<Octs>),
        }

        impl<Octs: AsRef<[u8]>> AllValues<Octs> {
            /// Parses any service bindings parameter value.
            ///
            /// If a known variant fails to parse, returns it as the unknown
            /// variant instead.
            ///
            /// # Panics
            ///
            /// Panics if taking the remaining octets from the parser fails.
            pub(super) fn parse_any<'a, Src>(
                key: SvcParamKey,
                parser: &mut Parser<'a, Src>,
            ) -> Self
            where Src: Octets<Range<'a> = Octs> + ?Sized {
                let pos = parser.pos();
                let res = match key {
                    $(
                        $type::KEY => {
                            $type::parse(
                                parser
                            ).map(Self::$type)
                        }
                    )+
                    _ => {
                        UnknownSvcParam::parse(
                            key, parser
                        ).map(Self::Unknown)
                    }
                };
                if let Ok(res) = res {
                    return res
                }
                parser.seek(pos).expect("invalid SvcParams");
                let octets = parser.parse_octets(
                    parser.remaining()
                ).expect("invalid SvcParams");

                Self::Unknown(unsafe {
                    UnknownSvcParam::new_unchecked(key, octets)
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

        impl<Octs> From<UnknownSvcParam<Octs>> for AllValues<Octs> {
            fn from(p: UnknownSvcParam<Octs>) -> Self {
                Self::Unknown(p)
            }
        }

        //--- SvcParamValue et al.

        impl<Octs> SvcParamValue for AllValues<Octs> {
            fn key(&self) -> SvcParamKey {
                match self {
                    $(
                        Self::$type(v) => v.key(),
                    )+
                    Self::Unknown(v) => v.key(),
                }
            }
        }

        impl<'a, Octs> ParseSvcParamValue<'a, Octs>
        for AllValues<Octs::Range<'a>>
        where Octs: Octets + ?Sized {
            fn parse_value(
                key: SvcParamKey,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                match key {
                    $(
                        $type::KEY => {
                            $type::parse(
                                parser
                            ).map(|res| Some(Self::$type(res)))
                        }
                    )+
                    _ => {
                        UnknownSvcParam::parse_value(
                            key, parser
                        ).map(|res| res.map(Self::Unknown))
                    }
                }
            }
        }

        impl<Octs: AsRef<[u8]>> ComposeSvcParamValue for AllValues<Octs> {
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
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

//============ Individual Value Types ========================================

//------------ octets_wrapper ------------------------------------------------

/// Defines the standard methods for a parameter type wrapping octets.
macro_rules! octets_wrapper {
    ( $(#[$attr:meta])* $name:ident => $key:ident) => {
        $(#[$attr])*
        #[derive(Debug, Clone)]
        #[repr(transparent)]
        pub struct $name<Octs: ?Sized>(Octs);

        impl $name<()> {
            /// The key for this type.
            const KEY: SvcParamKey = SvcParamKey::$key;
        }

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
            #[must_use]
            pub unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
                // SAFETY: Self has repr(transparent)
                mem::transmute(slice)
            }
        }

        impl<Octs: ?Sized> $name<Octs> {
            /// Returns a reference to the underlying octets sequence.
            pub fn as_octets(&self) -> &Octs {
                &self.0
            }

            /// Returns a slice of the underlying octets sequence.
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

        //--- SvcParamValue et al.

        impl<Octs: ?Sized> SvcParamValue for $name<Octs> {
            fn key(&self) -> SvcParamKey {
                $name::KEY
            }
        }

        impl<'a, Octs> ParseSvcParamValue<'a, Octs> for $name<Octs::Range<'a>>
        where Octs: Octets + ?Sized {
            fn parse_value(
                key: SvcParamKey,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                if key == $name::KEY {
                    Self::parse(parser).map(Some)
                }
                else {
                    Ok(None)
                }
            }
        }

        impl<Octs: AsRef<[u8]> + ?Sized> ComposeSvcParamValue for $name<Octs> {
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

    ($(#[$attr:meta])* $name:ident => $key:ident, $iter:ident) => {
        octets_wrapper!( $(#[$attr])* $name => $key);

        impl<Octs: AsRef<[u8]> + ?Sized> $name<Octs> {
            /// Returns an iterator over the elements of the value.
            pub fn iter(&self) -> $iter<'_, Octs> {
                $iter {
                    parser: Parser::from_ref(&self.0),
                }
            }
        }

        /// An iterator over the elements of the value.
        pub struct $iter<'a, Octs: ?Sized> {
            parser: Parser<'a, Octs>,
        }
    };
}

//------------ Mandatory -----------------------------------------------------

octets_wrapper!(
    /// The “mandatory” service parameter value.
    ///
    /// This value type lists the keys of the values that are considered
    /// essential for interpretation of the service binding. A client must
    /// understand all these keys in order be able to use a service bindings
    /// record.
    ///
    /// A value of this type wraps an octets sequence that contains the
    /// integer values of the keys in network byte order. You can create a
    /// value of this type by providing an iterator over the keys to be
    /// included to the [`from_keys`][Self::from_keys] function. You can
    /// get an iterator over the keys in an existing value through the
    /// [`iter`][Self::iter] method.
    Mandatory => MANDATORY,
    MandatoryIter
);

impl<Octs: AsRef<[u8]>> Mandatory<Octs> {
    /// Creates a new mandatory value from an octets sequence.
    ///
    /// The function checks that the octets sequence contains a properly
    /// encoded value of at most 65,535 octets. It does not check whether
    /// there are any duplicates in the data.
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Mandatory::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Mandatory<[u8]> {
    /// Creates a new mandatory value from an octets slice.
    ///
    /// The function checks that the octets slice contains a properly
    /// encoded value of at most 65,535 octets. It does not check whether
    /// there are any duplicates in the data.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Checks that a slice contains a properly encoded mandatory value.
    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongSvcParam::check_len(slice.len())?;
        if slice.len() % usize::from(SvcParamKey::COMPOSE_LEN) != 0 {
            return Err(ParseError::form_error(
                "invalid mandatory parameter",
            ));
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Mandatory<Octs> {
    /// Creates a new value from a list of keys.
    ///
    /// The created value will contain all the keys returned by the iterator
    /// in the order provided. The function does not check for duplicates.
    ///
    /// Returns an error if the octets builder runs out of space or the
    /// resulting value would be longer than 65,535 octets.
    pub fn from_keys(
        keys: impl Iterator<Item = SvcParamKey>,
    ) -> Result<Self, BuildValueError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut octets = EmptyBuilder::empty();
        for item in keys {
            item.compose(&mut octets)?;
        }
        let octets = Octs::from_builder(octets);
        if LongSvcParam::check_len(octets.as_ref().len()).is_err() {
            return Err(BuildValueError::LongSvcParam);
        }
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl<Octs: AsRef<[u8]>> Mandatory<Octs> {
    /// Parses a mandatory value from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

//--- Iterator

impl<Octs: Octets + ?Sized> Iterator for MandatoryIter<'_, Octs> {
    type Item = SvcParamKey;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(
            SvcParamKey::parse(&mut self.parser)
                .expect("invalid mandatory parameter"),
        )
    }
}

//--- Display

impl<Octs: Octets + ?Sized> fmt::Display for Mandatory<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

//--- Extend SvcParams and SvcParamsBuilder

impl<Octs: Octets + ?Sized> SvcParams<Octs> {
    /// Returns the content of the ‘mandatory’ value if present.
    pub fn mandatory(&self) -> Option<Mandatory<Octs::Range<'_>>> {
        self.first()
    }
}

impl<Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> SvcParamsBuilder<Octs> {
    /// Adds a ‘mandatory’ value with the given keys.
    ///
    /// Returns an error if there already is a ‘mandatory’ value, `keys`
    /// contains more values than fit into a service binding parameter value,
    /// or the underlying octets builder runs out of space.
    pub fn mandatory(
        &mut self,
        keys: impl AsRef<[SvcParamKey]>,
    ) -> Result<(), PushValueError> {
        self.push_raw(
            Mandatory::KEY,
            u16::try_from(
                keys.as_ref().len() * usize::from(SvcParamKey::COMPOSE_LEN),
            )
            .map_err(|_| PushValueError::LongSvcParam)?,
            |octs| {
                keys.as_ref().iter().try_for_each(|item| item.compose(octs))
            },
        )
        .map_err(Into::into)
    }
}

//------------ Alpn ----------------------------------------------------------

octets_wrapper!(
    /// The application layer protocols supported by the service endpoint.
    ///
    /// This value lists the protocol names supported by the service endpoint
    /// described by the service binding’s target name and, if present, port.
    /// The names are the same as used by Application Layer Protocol
    /// Negotiation (ALPN) described in [RFC 7301]. Each scheme that uses
    /// service bindings defines a set of default protocols that are quietly
    /// added to this list unless the [`NoDefaultAlpn`] value is present as
    /// well. For HTTPS, this default set consists of the `"http/1.1"`
    /// protocol.
    ///
    /// The wire format of this value consists of those protocol names each
    /// preceeded by a `u8` giving their length.
    ///
    /// The `iter` method produces an iterator over the individual protocol
    /// names in the value.
    Alpn => ALPN,
    AlpnIter
);

impl<Octs: AsRef<[u8]>> Alpn<Octs> {
    /// Creates an ALPN value from the underlying octets.
    ///
    /// The function ensures that `octets` is a correctly encoded ALPN
    /// value. It does not, however, check that the protocol identifiers
    /// are valid.
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Alpn::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Alpn<[u8]> {
    /// Creates an ALPN value from an octets slice.
    ///
    /// The function ensures that `slice` is a correctly encoded ALPN
    /// value. It does not, however, check that the protocol identifiers
    /// are valid.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Checks that a slice is a correctly encoded ALPN value.
    ///
    /// Checks for the length and that there is a sequence of elements each
    /// preceeded by its length.
    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongSvcParam::check_len(slice.len())?;
        let mut parser = Parser::from_ref(slice);
        while parser.remaining() > 0 {
            let len = usize::from(u8::parse(&mut parser)?);
            parser.advance(len)?;
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Alpn<Octs> {
    /// Parses an ALPN value from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

//--- Iterator

impl<'a, Octs: Octets + ?Sized> Iterator for AlpnIter<'a, Octs> {
    type Item = Octs::Range<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        let len = usize::from(
            u8::parse(&mut self.parser).expect("invalid alpn parameter"),
        );
        Some(
            self.parser
                .parse_octets(len)
                .expect("invalid alpn parameter"),
        )
    }
}

//--- Display

impl<Octs: Octets + ?Sized> fmt::Display for Alpn<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

//--- Extend SvcParams and SvcParamsBuilder

impl<Octs: Octets + ?Sized> SvcParams<Octs> {
    /// Returns the content of the ‘mandatory’ value if present.
    pub fn alpn(&self) -> Option<Alpn<Octs::Range<'_>>> {
        self.first()
    }
}

impl<Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> SvcParamsBuilder<Octs> {
    /// Adds an ALPN value to the parameters.
    ///
    /// The ALPN protocol names to be included in the value must be provided
    /// as a slice of those names in order to be able to calculate
    /// the length of the value up front.
    ///
    /// Returns an error if there already is an ALPN value, or if `protocols`
    /// contains more values than fit into a service binding parameter value,
    /// or the underlying octets builder runs out of space.
    pub fn alpn(&mut self, protocols: &[&[u8]]) -> Result<(), PushAlpnError> {
        // Check that everything is a-okay.
        let mut len = 0u16;
        for proto in protocols.iter() {
            let proto_len = u8::try_from(proto.len())
                .map_err(|_| PushAlpnError::InvalidProtocol)?;
            len = len
                .checked_add(u16::from(proto_len) + u8::COMPOSE_LEN)
                .ok_or(PushAlpnError::LongSvcParam)?;
        }
        self.push_raw(Alpn::KEY, len, |octs| {
            protocols.iter().try_for_each(|proto| {
                u8::try_from(proto.len())
                    .expect("long protocol")
                    .compose(octs)?;
                octs.append_slice(proto)
            })
        })
        .map_err(Into::into)
    }
}

//------------ AlpnBuilder ---------------------------------------------------

/// A builder for [`Alpn`] value content.
#[derive(Clone, Debug)]
pub struct AlpnBuilder<Target> {
    /// The octets builder to append to.
    target: Target,
}

impl<Target> AlpnBuilder<Target> {
    /// Creates a new, empty ALPN value builder.
    #[must_use]
    pub fn empty() -> Self
    where
        Target: EmptyBuilder,
    {
        AlpnBuilder {
            target: Target::empty(),
        }
    }

    /// Appends the given protocol name to the builder.
    ///
    /// Returns an error if the name is too long or the ALPN value would
    /// become too long or the underlying octets builder runs out of space.
    pub fn push(
        &mut self,
        protocol: impl AsRef<[u8]>,
    ) -> Result<(), BuildAlpnError>
    where
        Target: OctetsBuilder + AsRef<[u8]>,
    {
        let protocol = protocol.as_ref();
        if protocol.is_empty() {
            return Err(BuildAlpnError::InvalidProtocol);
        }
        let len = u8::try_from(protocol.len())
            .map_err(|_| BuildAlpnError::InvalidProtocol)?;
        LongSvcParam::check_len(
            self.target
                .as_ref()
                .len()
                .checked_add(protocol.len() + 1)
                .expect("long Alpn value"),
        )
        .map_err(|_| BuildAlpnError::LongSvcParam)?;
        len.compose(&mut self.target)?;
        self.target
            .append_slice(protocol)
            .map_err(|_| BuildAlpnError::ShortBuf)
    }

    /// Converts the builder into an imutable ALPN value.
    pub fn freeze(self) -> Alpn<Target::Octets>
    where
        Target: FreezeBuilder,
    {
        unsafe { Alpn::from_octets_unchecked(self.target.freeze()) }
    }
}

//------------ NoDefaultAlpn -------------------------------------------------

/// A signal to not include the service’s default ALPNs in the ALPN set.
///
/// For each service that uses SVCB, a set of default [`Alpn`] protocols
/// is defined. This set will be included even if they are not explicitely
/// provided via the ALPN value. The no-default-alpn value can be used to
/// signal that they should not be included.
///
/// This value is always empty.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NoDefaultAlpn;

impl NoDefaultAlpn {
    /// The key for this type.
    const KEY: SvcParamKey = SvcParamKey::NO_DEFAULT_ALPN;
}

impl NoDefaultAlpn {
    /// Parses a no-default-alpn value from its wire-format.
    pub fn parse<Src: Octets + ?Sized>(
        _parser: &mut Parser<'_, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self)
    }
}

//--- SvcParamValue et al.

impl SvcParamValue for NoDefaultAlpn {
    fn key(&self) -> SvcParamKey {
        Self::KEY
    }
}

impl<'a, Octs: Octets + ?Sized> ParseSvcParamValue<'a, Octs>
    for NoDefaultAlpn
{
    fn parse_value(
        key: SvcParamKey,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if key == Self::KEY {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl ComposeSvcParamValue for NoDefaultAlpn {
    fn compose_len(&self) -> u16 {
        0
    }

    fn compose_value<Target: OctetsBuilder + ?Sized>(
        &self,
        _target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        Ok(())
    }
}

//--- Display

impl fmt::Display for NoDefaultAlpn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("nodefaultalpn")
    }
}

//--- Extend SvcParams and SvcParamsBuilder

impl<Octs: Octets + ?Sized> SvcParams<Octs> {
    /// Returns whether the [`NoDefaultAlpn`] value is present.
    pub fn no_default_alpn(&self) -> bool {
        self.first::<NoDefaultAlpn>().is_some()
    }
}

impl<Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> SvcParamsBuilder<Octs> {
    /// Adds the [`NoDefaultAlpn`] value.
    pub fn no_default_alpn(&mut self) -> Result<(), PushError> {
        self.push(&NoDefaultAlpn)
    }
}

//------------ Port ----------------------------------------------------------

/// The TCP or UDP port to connect to when using an endpoint.
///
/// If this value is missing, the default port for the service should be used.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Port(u16);

impl Port {
    /// The key for this type.
    const KEY: SvcParamKey = SvcParamKey::PORT;
}

impl Port {
    /// Creates a new port value with the given port.
    #[must_use]
    pub fn new(port: u16) -> Self {
        Port(port)
    }

    /// Parses a port value from its wire-format.
    pub fn parse<Src: Octets + ?Sized>(
        parser: &mut Parser<'_, Src>,
    ) -> Result<Self, ParseError> {
        u16::parse(parser).map(Port::new)
    }

    /// Returns the port of this value.
    #[must_use]
    pub fn port(self) -> u16 {
        self.0
    }
}

//--- SvcParamValue et al.

impl SvcParamValue for Port {
    fn key(&self) -> SvcParamKey {
        Self::KEY
    }
}

impl<'a, Octs: Octets + ?Sized> ParseSvcParamValue<'a, Octs> for Port {
    fn parse_value(
        key: SvcParamKey,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if key == Self::KEY {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl ComposeSvcParamValue for Port {
    fn compose_len(&self) -> u16 {
        u16::COMPOSE_LEN
    }

    fn compose_value<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.0.compose(target)
    }
}

//--- Display

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port={}", self.0)
    }
}

//--- Extend SvcParams and SvcParamsBuilder

impl<Octs: Octets + ?Sized> SvcParams<Octs> {
    /// Returns the content of the port value if present.
    pub fn port(&self) -> Option<Port> {
        self.first()
    }
}

impl<Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> SvcParamsBuilder<Octs> {
    /// Adds a port value with the given port number.
    pub fn port(&mut self, port: u16) -> Result<(), PushError> {
        self.push(&Port::new(port))
    }
}

//------------ Ech -----------------------------------------------------------

octets_wrapper!(
    /// The Encrypted Client Hello (ECH) service parameter value.
    ///
    /// This value holds the information necessary to connect to the service
    /// with Encrypted Client Hello. It contains all this information in
    /// wire-format to be used with the TLS ECH extension currently in
    /// development as Internet draft [draft-ietf-tls-esni].
    ///
    /// [draft-ietf-tls-esni]: https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
    Ech => ECH
);

impl<Octs: AsRef<[u8]>> Ech<Octs> {
    /// Creates a new ECH value from the given content.
    ///
    /// Returns an error if the content is too long to fit into an SVCB
    /// parameter value.
    pub fn from_octets(octets: Octs) -> Result<Self, LongSvcParam> {
        Ech::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Ech<[u8]> {
    /// Creates a new ECH value from a slice of the content.
    ///
    /// Returns an error if the slice is too long to fit into an SVCB
    /// parameter value.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, LongSvcParam> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Checks that a slice holds correct ECH content.
    ///
    /// This only checks the length.
    fn check_slice(slice: &[u8]) -> Result<(), LongSvcParam> {
        LongSvcParam::check_len(slice.len())?;
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Ech<Octs> {
    /// Parses an ECH value from its wire-format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
            .map_err(Into::into)
    }
}

//--- Display

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for Ech<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.as_slice().is_empty() {
            f.write_str("ech")
        } else {
            f.write_str("ech=")?;
            base64::display(self.as_slice(), f)
        }
    }
}

//--- Extend SvcParams and SvcParamsBuilder

impl<Octs: Octets + ?Sized> SvcParams<Octs> {
    /// Returns the content of the ECH value if present.
    pub fn ech(&self) -> Option<Ech<Octs::Range<'_>>> {
        self.first()
    }
}

impl<Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> SvcParamsBuilder<Octs> {
    /// Adds a port value with the given port number.
    pub fn ech<Source: AsRef<[u8]> + ?Sized>(
        &mut self,
        ech: &Source,
    ) -> Result<(), PushValueError> {
        self.push(Ech::from_slice(ech.as_ref())?)
            .map_err(Into::into)
    }
}

//------------ Ipv4Hint ------------------------------------------------------

octets_wrapper!(
    /// The ‘ipv4hint’ service parameter value.
    ///
    /// This values provides a list of IPv4 addresses that the client may use
    /// to connect to the endpoint. The value is intended to speed up
    /// connecting but not to replace the A query to get the actual IPv4
    /// addresses of the endpoint. That is, the client can start an A query
    /// and at the same time connect to an IP address from the value. If the
    /// A query doesn’t return this IP address, it may want to start again
    /// with an address from the response.
    ///
    /// The type contains the value in its wire format which consists of the
    /// sequence of IPv4 addresses.
    Ipv4Hint => IPV4HINT,
    Ipv4HintIter
);

impl<Octs: AsRef<[u8]>> Ipv4Hint<Octs> {
    /// Creates a new ipv4hint value from its content.
    ///
    /// The function returns an error if `octets` doesn’t contain a
    /// correctly encoded value or if it is longer than 65,535 octets.
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Ipv4Hint::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a new value from a list of IPv4 addresses.
    ///
    /// The function will fail if the iterator returns more than 16,383
    /// addresses or if the octets builder to be used for building runs out
    /// of space.
    pub fn from_addrs(
        addrs: impl IntoIterator<Item = Ipv4Addr>,
    ) -> Result<Self, BuildValueError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut octets = EmptyBuilder::empty();
        for item in addrs {
            item.compose(&mut octets)?;
        }
        let octets = Octs::from_builder(octets);
        if LongSvcParam::check_len(octets.as_ref().len()).is_err() {
            return Err(BuildValueError::LongSvcParam);
        }
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Ipv4Hint<[u8]> {
    /// Creates a new ipv4hint value from a slice of its content.
    ///
    /// The function returns an error if `slice` doesn’t contain a
    /// correctly encoded value or if it is longer than 65,535 octets.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Checks that a slice contains a correctly encoded ipv4hint value.
    ///
    /// It checks that the length is divisible by 4 and not longer than
    /// 65,535 octets.
    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongSvcParam::check_len(slice.len())?;
        if slice.len() % usize::from(Ipv4Addr::COMPOSE_LEN) != 0 {
            return Err(ParseError::form_error("invalid ipv4hint parameter"));
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Ipv4Hint<Octs> {
    /// Parses an ipv4hint value from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

impl<Octs: Octets + ?Sized> Iterator for Ipv4HintIter<'_, Octs> {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(
            Ipv4Addr::parse(&mut self.parser)
                .expect("invalid ipv4hint parameter"),
        )
    }
}

impl<Octs: Octets + ?Sized> fmt::Display for Ipv4Hint<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

//--- Extend SvcParams and SvcParamsBuilder

impl<Octs: Octets + ?Sized> SvcParams<Octs> {
    /// Returns the content of the ‘ipv4hint’ value if present.
    pub fn ipv4hint(&self) -> Option<Ipv4Hint<Octs::Range<'_>>> {
        self.first()
    }
}

impl<Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> SvcParamsBuilder<Octs> {
    /// Adds an ‘ipv4hint’ value with the given addresses.
    ///
    /// Returns an error if there already is an ‘ipv4hint’ value, `addrs`
    /// contains more values than fit into a service binding parameter value,
    /// or the underlying octets builder runs out of space.
    pub fn ipv4hint(
        &mut self,
        addrs: impl AsRef<[Ipv4Addr]>,
    ) -> Result<(), PushValueError> {
        self.push_raw(
            Ipv4Hint::KEY,
            u16::try_from(
                addrs.as_ref().len() * usize::from(Ipv4Addr::COMPOSE_LEN),
            )
            .map_err(|_| PushValueError::LongSvcParam)?,
            |octs| {
                addrs
                    .as_ref()
                    .iter()
                    .try_for_each(|item| item.compose(octs))
            },
        )
        .map_err(Into::into)
    }
}

//------------ Ipv6Hint ------------------------------------------------------

octets_wrapper!(
    /// The ‘ipv6hint’ service parameter value.
    ///
    /// This values provides a list of IPv6 addresses that the client may use
    /// to connect to the endpoint. The value is intended to speed up
    /// connecting but not to replace the AAAA query to get the actual IPv6
    /// addresses of the endpoint. That is, the client can start an AAAA query
    /// and at the same time connect to an IP address from the value. If the
    /// AAAA query doesn’t return this IP address, it may want to start again
    /// with an address from the response.
    ///
    /// The type contains the value in its wire format which consists of the
    /// sequence of IPv6 addresses.
    Ipv6Hint => IPV6HINT,
    Ipv6HintIter
);

impl<Octs: AsRef<[u8]>> Ipv6Hint<Octs> {
    /// Creates a new ipv6hint value from its content.
    ///
    /// The function returns an error if `octets` doesn’t contain a
    /// correctly encoded value or if it is longer than 65,535 octets.
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Ipv6Hint::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a new value from a list of IPv6 addresses.
    ///
    /// The function will fail if the iterator returns more than 16,383
    /// addresses or if the octets builder to be used for building runs out
    /// of space.
    pub fn from_addrs(
        addrs: impl IntoIterator<Item = Ipv6Addr>,
    ) -> Result<Self, BuildValueError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut octets = EmptyBuilder::empty();
        for item in addrs {
            item.compose(&mut octets)?;
        }
        let octets = Octs::from_builder(octets);
        if LongSvcParam::check_len(octets.as_ref().len()).is_err() {
            return Err(BuildValueError::LongSvcParam);
        }
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl Ipv6Hint<[u8]> {
    /// Creates a new ‘ipv6hint’ value from a slice of its content.
    ///
    /// The function returns an error if `slice` doesn’t contain a
    /// correctly encoded value or if it is longer than 65,535 octets.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Checks that a slice contains a correctly encoded ipv6hint value.
    ///
    /// It checks that the length is divisible by16 and not longer than
    /// 65,535 octets.
    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongSvcParam::check_len(slice.len())?;
        if slice.len() % usize::from(Ipv6Addr::COMPOSE_LEN) != 0 {
            return Err(ParseError::form_error("invalid ipv6hint parameter"));
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Ipv6Hint<Octs> {
    /// Parses an ‘ipv6hint’ value from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

//--- Iterator

impl<Octs: Octets + ?Sized> Iterator for Ipv6HintIter<'_, Octs> {
    type Item = Ipv6Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(
            Ipv6Addr::parse(&mut self.parser)
                .expect("invalid ipv6hint parameter"),
        )
    }
}

//--- Display

impl<Octs: Octets + ?Sized> fmt::Display for Ipv6Hint<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

//--- Extend SvcParams and SvcParamsBuilder

impl<Octs: Octets + ?Sized> SvcParams<Octs> {
    /// Returns the content of the ‘ipv6hint’ value if present.
    pub fn ipv6hint(&self) -> Option<Ipv6Hint<Octs::Range<'_>>> {
        self.first()
    }
}

impl<Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> SvcParamsBuilder<Octs> {
    /// Adds an ‘ipv6hint’ value with the given addresses.
    ///
    /// Returns an error if there already is an ‘ipv6hint’ value, `addrs`
    /// contains more values than fit into a service binding parameter value,
    /// or the underlying octets builder runs out of space.
    pub fn ipv6hint(
        &mut self,
        addrs: impl AsRef<[Ipv6Addr]>,
    ) -> Result<(), PushValueError> {
        self.push_raw(
            Ipv6Hint::KEY,
            u16::try_from(
                addrs.as_ref().len() * usize::from(Ipv6Addr::COMPOSE_LEN),
            )
            .map_err(|_| PushValueError::LongSvcParam)?,
            |octs| {
                addrs
                    .as_ref()
                    .iter()
                    .try_for_each(|item| item.compose(octs))
            },
        )
        .map_err(Into::into)
    }
}

//------------ DohPath -------------------------------------------------------

octets_wrapper!(
    /// The ‘dohpath’ service parameter value.
    ///
    /// This value includes the URI template to be used when directing
    /// DNS-over-HTTPS (DoH) queries to a service. This template is encoded
    /// as UTF-8. URI templates are described in
    /// [RFC 6570](https://www.rfc-editor.org/rfc/rfc6570)
    ///
    /// This value type is described as part of the specification for
    /// using service bindings with DNS-over-HTTPS, currently
    /// [draft-ietf-add-svcb-dns](https://datatracker.ietf.org/doc/html/draft-ietf-add-svcb-dns).
    DohPath => DOHPATH
);

impl<Octs: AsRef<[u8]>> DohPath<Octs> {
    /// Creates a ‘dohpath’ value from its content.
    ///
    /// Returns an error if `octets` is longer than 65,535 bytes.
    pub fn from_octets(octets: Octs) -> Result<Self, LongSvcParam> {
        DohPath::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl DohPath<[u8]> {
    /// Creates a ‘dohpath’ value from a slice of its content.
    ///
    /// Returns an error if `slice` is longer than 65,535 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, LongSvcParam> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Checkes that a slice is acceptable as ‘dohpath’ content.
    ///
    /// Only checks that the slice isn’t too long.
    fn check_slice(slice: &[u8]) -> Result<(), LongSvcParam> {
        LongSvcParam::check_len(slice.len())?;
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> DohPath<Octs> {
    /// Parses a ‘dohpath’ value from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
            .map_err(Into::into)
    }
}

//--- TryFrom and FromStr

impl<Octs: AsRef<[u8]>> TryFrom<Str<Octs>> for DohPath<Octs> {
    type Error = LongSvcParam;

    fn try_from(src: Str<Octs>) -> Result<Self, Self::Error> {
        Self::from_octets(src.into_octets())
    }
}

impl<Octs> FromStr for DohPath<Octs>
where
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder:
        EmptyBuilder + FreezeBuilder<Octets = Octs>,
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.as_slice().is_empty() {
            f.write_str("dohpath")
        } else {
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

//--- Extend SvcParams and SvcParamsBuilder

impl<Octs: Octets + ?Sized> SvcParams<Octs> {
    /// Returns the content of the ‘dohpath’ value if present.
    pub fn dohpath(&self) -> Option<DohPath<Octs::Range<'_>>> {
        self.first()
    }
}

impl<Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> SvcParamsBuilder<Octs> {
    /// Adds a ‘dohpath’ value with the URI template.
    ///
    /// Returns an error if there already is a ‘dohpath’ value, `template`
    /// is too long to fit in a service binding parameter value,
    /// or the underlying octets builder runs out of space.
    pub fn dohpath(&mut self, template: &str) -> Result<(), PushValueError> {
        self.push_raw(
            DohPath::KEY,
            u16::try_from(template.len())
                .map_err(|_| PushValueError::LongSvcParam)?,
            |octs| octs.append_slice(template.as_bytes()),
        )
        .map_err(Into::into)
    }
}

//============ BuildValueError ===============================================

//------------ BuildValueError -----------------------------------------------

/// An error happened while constructing an SVCB value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildValueError {
    /// The value would exceed the allow length of a value.
    LongSvcParam,

    /// The underlying octets builder ran out of buffer space.
    ShortBuf,
}

impl From<LongSvcParam> for BuildValueError {
    fn from(_: LongSvcParam) -> Self {
        Self::LongSvcParam
    }
}

impl<T: Into<ShortBuf>> From<T> for BuildValueError {
    fn from(_: T) -> Self {
        Self::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for BuildValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LongSvcParam => f.write_str("long SVCB value"),
            Self::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildValueError {}

//------------ PushValueError ------------------------------------------------

/// An error happened while constructing an SVCB value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushValueError {
    /// A value with this key is already present.
    DuplicateKey,

    /// The value would exceed the allow length of a value.
    LongSvcParam,

    /// The underlying octets builder ran out of buffer space.
    ShortBuf,
}

impl From<LongSvcParam> for PushValueError {
    fn from(_: LongSvcParam) -> Self {
        Self::LongSvcParam
    }
}

impl From<PushError> for PushValueError {
    fn from(src: PushError) -> Self {
        match src {
            PushError::DuplicateKey => Self::DuplicateKey,
            PushError::ShortBuf => Self::ShortBuf,
        }
    }
}

impl From<BuildValueError> for PushValueError {
    fn from(src: BuildValueError) -> Self {
        match src {
            BuildValueError::LongSvcParam => Self::LongSvcParam,
            BuildValueError::ShortBuf => Self::ShortBuf,
        }
    }
}

impl<T: Into<ShortBuf>> From<T> for PushValueError {
    fn from(_: T) -> Self {
        Self::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for PushValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey => f.write_str("duplicate key"),
            Self::LongSvcParam => f.write_str("long SVCB value"),
            Self::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushValueError {}

//------------ BuildAlpnError ------------------------------------------------

/// An error happened while constructing an SVCB value.
#[derive(Clone, Copy, Debug)]
pub enum BuildAlpnError {
    /// The protocol value is not valid.
    ///
    /// It was either empty or longer than 255 octets.
    InvalidProtocol,

    /// The value would exceed the allow length of a value.
    LongSvcParam,

    /// The underlying octets builder ran out of buffer space.
    ShortBuf,
}

impl<T: Into<ShortBuf>> From<T> for BuildAlpnError {
    fn from(_: T) -> Self {
        Self::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for BuildAlpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocol => f.write_str("invalid ALPN protocol"),
            Self::LongSvcParam => f.write_str("long SVCB value"),
            Self::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildAlpnError {}

//------------ PushAlpnError -------------------------------------------------

/// An error happened while constructing an SVCB value.
#[derive(Clone, Copy, Debug)]
pub enum PushAlpnError {
    /// A value with this key is already present.
    DuplicateKey,

    /// The protocol value is not valid.
    ///
    /// It was either empty or longer than 255 octets.
    InvalidProtocol,

    /// The value would exceed the allow length of a value.
    LongSvcParam,

    /// The underlying octets builder ran out of buffer space.
    ShortBuf,
}

impl From<PushError> for PushAlpnError {
    fn from(src: PushError) -> Self {
        match src {
            PushError::DuplicateKey => Self::DuplicateKey,
            PushError::ShortBuf => Self::ShortBuf,
        }
    }
}

impl From<BuildValueError> for PushAlpnError {
    fn from(src: BuildValueError) -> Self {
        match src {
            BuildValueError::LongSvcParam => Self::LongSvcParam,
            BuildValueError::ShortBuf => Self::ShortBuf,
        }
    }
}

impl<T: Into<ShortBuf>> From<T> for PushAlpnError {
    fn from(_: T) -> Self {
        Self::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for PushAlpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey => f.write_str("duplicate key"),
            Self::InvalidProtocol => f.write_str("invalid ALPN protocol"),
            Self::LongSvcParam => f.write_str("long SVCB value"),
            Self::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushAlpnError {}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vectors_alpn_escape() {
        let mut parser = Parser::from_ref(
            b"\
            \x08\
            \x66\x5c\x6f\x6f\x2c\x62\x61\x72\
            \x02\
            \x68\x32\
        "
            .as_ref(),
        );
        let alpn = Alpn::parse(&mut parser).unwrap();
        assert_eq!(parser.remaining(), 0);
        assert!(alpn.iter().eq([br"f\oo,bar".as_ref(), b"h2".as_ref(),]));
    }
}
