// Implementation of SVCB RR type
// https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-08#section-8

use crate::base::iana::{Rtype, SvcbParamKey};
use crate::base::name::{Dname, ParsedDname, PushError, ToDname};
use crate::base::octets::{
    Compose, Composer, EmptyBuilder, FormError,
    FromBuilder, Octets, OctetsBuilder, OctetsFrom, OctetsInto, Parse,
    ParseError, Parser, ShortBuf,
};
use crate::base::rdata::{ComposeRecordData, ParseRecordData, RecordData};
use octseq::array::Array;
use octseq::builder::FreezeBuilder;
use core::{fmt, hash};
use param::{AllParams, SvcbParam};

// Types in SVCB type group are based on the same format.
macro_rules! svcb_types {
    ($($name:ident,)+) => {
        $(
/// Struct has priority and target decoded, but not parameters.
/// Provides a [`iter`](Svcb::iter) method to iterate through each parameter.
#[derive(Clone)]
pub struct $name<O, N> {
    priority: u16,
    target: N,
    params: O,
    sorter: Sorter,
}

impl<O, N> $name<O, N> {
    /// Create a new SVCB(or its siblings) with given arguments.
    ///
    /// # Examples
    ///
    /// To parse a SVCB record
    /// ```ignore
    /// let rdata = SVCB::new(1, dname, octets);
    /// for param in rdata.iter() {
    ///     ...
    /// }
    /// ```
    /// To build a SCVB record
    /// ```ignore
    /// let rdata = SCVB::new(1, dname, octets_builder);
    /// rdata.push(param1)?;
    /// rdata.push(param2)?;
    /// rdata.freeze();
    /// ```
    pub fn new(priority: u16, target: N, params: O) -> Self {
        Self {
            priority,
            target,
            params,
            sorter: Default::default(),
        }
    }

    /// Get the priority.
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Get the target. Note the target won't be translated to owner
    /// automatically in service mode if it equals to root.
    pub fn target(&self) -> &N {
        &self.target
    }

    pub(super) fn convert_octets<TOcts, TName>(
        self
    ) -> Result<$name<TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<O>,
        TName: OctetsFrom<N, Error = TOcts::Error>,
    {
        Ok($name {
            priority: self.priority,
            target: self.target.try_octets_into()?,
            params: self.params.try_octets_into()?,
            sorter: self.sorter,
        })
    }
}

impl<'a, Octs: Octets> $name<Octs::Range<'a>, ParsedDname<'a, Octs>> {
    pub fn flatten_into<Target>(
        self,
    ) -> Result<$name<Target, Dname<Target>>, PushError>
    where
        Target: OctetsFrom<Octs::Range<'a>> + FromBuilder,
        <Target as FromBuilder>::Builder: EmptyBuilder,
        PushError: From<<Target as OctetsFrom<Octs::Range<'a>>>::Error>,
    {
        let Self {
            priority,
            target,
            params,
            ..
        } = self;
        Ok($name::new(
            priority,
            target.flatten_into()?,
            params.try_octets_into()?,
        ))
    }
}

impl<'a, Octs: Octets + ?Sized> $name<Octs::Range<'a>, ParsedDname<'a, Octs>> {
    pub fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let priority = u16::parse(parser)?;
        let target = ParsedDname::parse(parser)?;
        let len = parser.remaining();
        let params = parser.parse_octets(len)?;
        Ok(Self::new(priority, target, params))
    }
}

impl<O, OO, N, NN> OctetsFrom<$name<O, N>> for $name<OO, NN>
where
    OO: OctetsFrom<O>,
    NN: OctetsFrom<N>,
    OO::Error: From<NN::Error>,
{
    type Error = OO::Error;

    fn try_octets_from(source: $name<O, N>) -> Result<Self, Self::Error> {
        Ok($name::new(
            source.priority,
            NN::try_octets_from(source.target)?,
            OO::try_octets_from(source.params)?,
        ))
    }
}

impl<OB: OctetsBuilder, N> $name<OB, N> {
    /// Freeze the internal OctetsBuilder.
    pub fn freeze(self) -> $name<OB::Octets, N>
    where OB: FreezeBuilder {
        $name {
            priority: self.priority,
            target: self.target,
            params: self.params.freeze(),
            sorter: self.sorter,
        }
    }
}

impl<OB: Composer, N> $name<OB, N> {
    /// Push a parameter into the builder.
    pub fn push<O: AsRef<[u8]>>(
        &mut self,
        param: AllParams<O>,
    ) -> Result<(), ShortBuf> {
        let key = param.key().into();
        let off = self.params.as_ref().len();
        param.compose(&mut self.params).map_err(Into::into)?;
        let len = self.params.as_ref().len() - off;
        self.sorter.insert(key, off as u16, len as u16)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<O, N> RecordData for $name<O, N> {
    fn rtype(&self) -> Rtype {
        Rtype::$name
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
for $name<Octs::Range<'a>, ParsedDname<'a, Octs>> {
    fn parse_rdata(
        rtype: Rtype, parser: &mut Parser<'a, Octs>
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::$name {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Octs, Name> ComposeRecordData for $name<Octs, Name>
where Octs: AsRef<[u8]>, Name: ToDname {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u16::checked_add(
                u16::COMPOSE_LEN + self.target.compose_len(),
                self.params.as_ref().len().try_into().expect("long params")
            ).expect("long record data")
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.priority.compose(target)?;
        self.target.compose(target)?;

        let view = self.sorter.buf.as_slice();
        let mut bytes = [0u8; 2];
        for chunk in view.chunks_exact(Sorter::CHUNK_SIZE) {
            bytes[0] = chunk[2];
            bytes[1] = chunk[3];
            let off = u16::from_ne_bytes(bytes).into();
            bytes[0] = chunk[4];
            bytes[1] = chunk[5];
            let len: usize = u16::from_ne_bytes(bytes).into();
            let slice = &self.params.as_ref()[off..off + len];
            target.append_slice(slice)?;
        }

        Ok(())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

impl<O: AsRef<[u8]>, N: ToDname> $name<O, N> {
    /// Compose without checking for the order of parameters.
    pub fn compose_unchecked<Target: Composer + ?Sized>(
        &self, buf: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.priority.compose(buf)?;
        self.target.compose(buf)?;
        buf.append_slice(self.params.as_ref())
    }
}

impl<O: Octets, N> $name<O, N> {
    pub fn iter(&self) -> ParamIter<'_, O> {
        ParamIter { parser: Parser::from_ref(&self.params) }
    }
}

//--- Display and Debug
impl<O, N> fmt::Display for $name<O, N>
where
    O: Octets,
    N: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.priority, self.target)?;
        for param in self.iter() {
            write!(f, " {}", param.map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}

impl<O, N> fmt::Debug for $name<O, N>
where
    O: Octets,
    N: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {:?}", self.priority, self.target)?;
        for param in self.iter() {
            write!(f, " {}", param.map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}

//--- PartialEq and Eq

impl<O, OO, N, NN> PartialEq<$name<OO, NN>> for $name<O, N>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &$name<OO, NN>) -> bool {
        self.priority == other.priority
            && self.target.name_eq(&other.target)
            && self.params.as_ref() == other.params.as_ref()
    }
}

impl<O: AsRef<[u8]>, N: ToDname> Eq for $name<O, N> {}

//--- Hash

impl<O: AsRef<[u8]>, N: hash::Hash> hash::Hash for $name<O, N> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.priority.hash(state);
        self.target.hash(state);
        self.params.as_ref().hash(state);
    }
}
        )+
    }
}

svcb_types!(Svcb, Https,);

// This is a helper type to sort parameters without allocation. It
// uses internal buffer to keep parameter key sorted. With the
// additional offset and length recorded when the parameter was
// pushed, it reorder them during composing.
//
// FIXME: Using a fixed length buffer is not ideal, the size should be
// big enough.
#[derive(Clone, Default)]
struct Sorter {
    n: usize,
    buf: Array<512>,
}

impl Sorter {
    // key + off + len
    const CHUNK_SIZE: usize = 6;
    fn insert(
        &mut self,
        key: u16,
        off: u16,
        len: u16,
    ) -> Result<(), ShortBuf> {
        let end = self.buf.len();

        // allocate space by appending an empty chunck
        self.buf.append_slice(&[0u8; Self::CHUNK_SIZE])?;

        let view = &self.buf.as_slice()[..end];
        let target =
            view.chunks_exact(Self::CHUNK_SIZE)
                .enumerate()
                .find(|(_, c)| {
                    let mut key_buf = [0u8; 2];
                    key_buf[0] = c[0];
                    key_buf[1] = c[1];
                    key <= u16::from_ne_bytes(key_buf)
                });

        let buf = match target {
            None => &mut self.buf.as_slice_mut()[end..end + Self::CHUNK_SIZE],
            Some((i, _)) => {
                let view = &mut self.buf.as_slice_mut()
                    [i * Self::CHUNK_SIZE..end + Self::CHUNK_SIZE];
                view.rotate_right(Self::CHUNK_SIZE);
                &mut view[..Self::CHUNK_SIZE]
            }
        };
        let bytes = key.to_ne_bytes();
        buf[0] = bytes[0];
        buf[1] = bytes[1];
        let bytes = off.to_ne_bytes();
        buf[2] = bytes[0];
        buf[3] = bytes[1];
        let bytes = len.to_ne_bytes();
        buf[4] = bytes[0];
        buf[5] = bytes[1];
        self.n += 1;
        Ok(())
    }
}

/// A iterator to parse each parameter.
pub struct ParamIter<'a, Octs> {
    parser: Parser<'a, Octs>,
}

impl<'a, Octs: Octets> Iterator for ParamIter<'a, Octs> {
    type Item = Result<AllParams<Octs::Range<'a>>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.remaining() == 0 {
            return None;
        }
        Some(AllParams::parse(&mut self.parser))
    }
}

pub mod param {
    use super::*;
    use crate::base::net::{Ipv4Addr, Ipv6Addr};
    use core::convert::TryInto;
    use core::fmt::{self, Write};

    macro_rules! param_enum {
        ($($name:ident($type:ident $( < $( $type_arg:ident ),* > )*),)+) => {
            /// A enum to hold all the parameters.
            #[derive(Debug, Clone, Eq, PartialEq)]
            pub enum AllParams<Octs> {
                $($name( $type $( < $( $type_arg ),* > )* )),+
            }

            impl<Octs: AsRef<[u8]>> SvcbParam for AllParams<Octs> {
                fn key(&self) -> SvcbParamKey {
                    match self {
                        $(Self::$name(v) => v.key()),+
                    }
                }

                fn param_len(&self) -> u16 {
                    match self {
                        $(Self::$name(v) => v.param_len()),+
                    }
                }
            }

            impl<Octs> AllParams<Octs> {
                pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
                    parser: &mut Parser<'a, Src>
                ) -> Result<Self, ParseError> {
                    let key = parser.parse_u16()?.into();
                    let len = parser.parse_u16()?.into();
                    let mut parser = parser.parse_parser(len)?;
                    let res = AllParams::parse_value(&mut parser, key)?;
                    if parser.remaining() > 0 {
                        return Err(ParseError::Form(
                            FormError::new("trailing data in option")
                        ))
                    }
                    Ok(res)
                }
            }

            impl<Octs: AsRef<[u8]>> AllParams<Octs> {
                pub fn compose<Target: OctetsBuilder + ?Sized>(
                    &self, buf: &mut Target
                ) -> Result<(), Target::AppendError> {
                    let key: u16 = self.key().into();
                    key.compose(buf)?;
                    self.param_len().compose(buf)?;
                    match self {
                        $(Self::$name(v) => v.compose(buf)),+
                    }
                }
            }

            $(
                impl<Octs> From<$type $( < $( $type_arg ),* > )*>
                for AllParams<Octs> {
                    fn from(p: $type $( < $( $type_arg ),* > )*) -> Self {
                        AllParams::$name(p)
                    }
                }
            )+

            impl<O: Octets> fmt::Display for AllParams<O> {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    match self {
                        $(Self::$name(v) => v.fmt(f)?),+
                    }
                    Ok(())
                }
            }
        };
    }

    param_enum!(
        Mandatory(Mandatory<Octs>),
        Alpn(Alpn<Octs>),
        NoDefaultAlpn(NoDefaultAlpn),
        Port(Port),
        Ech(Ech<Octs>),
        Ipv4Hint(Ipv4Hint<Octs>),
        Ipv6Hint(Ipv6Hint<Octs>),
        DohPath(DohPath<Octs>),
        Unknown(Unknown<Octs>),
    );

    /// Basic trait for SVCB parameters.
    pub trait SvcbParam {
        fn key(&self) -> SvcbParamKey;

        fn param_len(&self) -> u16;
    }

    impl<Octs> AllParams<Octs> {
        fn parse_value<'a, POcts: Octets<Range<'a> = Octs> + ?Sized>(
            parser: &mut Parser<'a, POcts>,
            key: SvcbParamKey,
        ) -> Result<Self, ParseError> {
            let val = match key {
                SvcbParamKey::Mandatory => Mandatory::parse(parser)?.into(),
                SvcbParamKey::Alpn => Alpn::parse(parser)?.into(),
                SvcbParamKey::NoDefaultAlpn => {
                    NoDefaultAlpn::parse(parser)?.into()
                }
                SvcbParamKey::Port => Port::parse(parser)?.into(),
                SvcbParamKey::Ipv4Hint => Ipv4Hint::parse(parser)?.into(),
                SvcbParamKey::Ech => Ech::parse(parser)?.into(),
                SvcbParamKey::Ipv6Hint => Ipv6Hint::parse(parser)?.into(),
                _ => Unknown::new(
                    key,
                    parser.parse_octets(parser.remaining())?,
                )
                .into(),
            };
            Ok(val)
        }
    }

    // for types wraps an octets
    macro_rules! octets_wrapper {
        ($name:ident) => {
            /// A SVCB parameter.
            #[derive(Debug, Clone, Eq, PartialEq)]
            pub struct $name<Octs>(Octs);

            impl<Octs> $name<Octs> {
                pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
                    parser: &mut Parser<'a, Src>
                ) -> Result<Self, ParseError> {
                    //let len = u16::parse(parser)?;
                    //let data = parser.parse_octets(len.into())?;
                    let data = parser.parse_octets(parser.remaining())?;
                    Ok(Self(data))
                }
            }

            impl<O: AsRef<[u8]>> $name<O> {
                fn compose<Target: OctetsBuilder + ?Sized>(
                    &self, target: &mut Target
                ) -> Result<(), Target::AppendError> {
                    target.append_slice(self.0.as_ref())
                }
            }

            impl<O: AsRef<[u8]>> SvcbParam for $name<O> {
                fn key(&self) -> SvcbParamKey {
                    SvcbParamKey::$name
                }

                fn param_len(&self) -> u16 {
                    self.0.as_ref().len().try_into().expect("long param")
                }
            }

            impl<Octs> $name<Octs> {
                /// Create a new parameter from octets.
                pub fn new(o: Octs) -> Self {
                    Self(o)
                }
            }
            impl<OB: OctetsBuilder + FreezeBuilder> $name<OB> {
                /// Freeze the internal OctetsBuilder.
                pub fn freeze(self) -> $name<OB::Octets> {
                    $name(self.0.freeze())
                }
            }

            impl<Octs> $name<Octs> {
                pub fn for_ref(&self) -> $name<&Octs> {
                    $name(&self.0)
                }
            }

            impl<O: AsRef<[u8]>> $name<O> {
                pub fn for_slice(&self) -> $name<&[u8]> {
                    $name(self.0.as_ref())
                }
            }

            impl<O: AsRef<[u8]>> $name<O> {
                pub fn as_slice(&self) -> &[u8] {
                    self.0.as_ref()
                }
            }

            impl<Octs: AsRef<T>, T> AsRef<T> for $name<Octs> {
                fn as_ref(&self) -> &T {
                    self.0.as_ref()
                }
            }

            impl<O, OO> OctetsFrom<$name<O>> for $name<OO>
            where
                OO: OctetsFrom<O>,
            {
                type Error = OO::Error;

                fn try_octets_from(
                    source: $name<O>,
                ) -> Result<Self, Self::Error> {
                    Ok($name::new(OO::try_octets_from(source.0)?))
                }
            }
        };
        ($name:ident, $iter:ident) => {
            octets_wrapper!($name);

            impl<Octs: AsRef<[u8]>> $name<Octs> {
                /// Iterate over the internal items.
                pub fn iter(&self) -> $iter<'_, Octs> {
                    $iter {
                        parser: Parser::from_ref(&self.0),
                    }
                }
            }

            /// An iterator type to parse the internal items.
            pub struct $iter<'a, Octs> {
                parser: Parser<'a, Octs>,
            }
        };
    }

    octets_wrapper!(Mandatory, MandatoryIter);

    impl<OB: Composer> Mandatory<OB> {
        pub fn push(
            &mut self, key: SvcbParamKey
        ) -> Result<(), OB::AppendError> {
            u16::from(key).compose(&mut self.0)
        }
    }

    impl<'a, Octs: Octets> Iterator for MandatoryIter<'a, Octs> {
        type Item = Result<SvcbParamKey, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            Some(
                self.parser
                    .parse_u16()
                    .map(|v| v.into())
                    .map_err(Into::into),
            )
        }
    }

    impl<Octs: Octets> fmt::Display for Mandatory<Octs> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            for (i, v) in self.iter().enumerate() {
                let v = v.map_err(|_| fmt::Error)?;
                if i == 0 {
                    write!(f, "mandatory={}", v)?;
                } else {
                    write!(f, ",{}", v)?;
                }
            }
            Ok(())
        }
    }

    octets_wrapper!(Alpn, AlpnIter);

    impl<OB: Composer> Alpn<OB> {
        pub fn push<O: AsRef<[u8]>>(
            &mut self,
            name: O,
        ) -> Result<(), ShortBuf> {
            let name = name.as_ref();
            let len: u8 = name.len().try_into().map_err(|_| ShortBuf)?;
            len.compose(&mut self.0).map_err(Into::into)?;
            self.0.append_slice(name).map_err(Into::into)
        }
    }

    impl<'a, Octs: Octets> Iterator for AlpnIter<'a, Octs> {
        type Item = Result<Octs::Range<'a>, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            Some(
                self.parser
                    .parse_u8()
                    .and_then(|len| self.parser.parse_octets(len.into()))
                    .map_err(Into::into),
            )
        }
    }

    impl<Octs: Octets> fmt::Display for Alpn<Octs> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            for (i, v) in self.iter().enumerate() {
                let v = v.map_err(|_| fmt::Error)?;
                if i == 0 {
                    f.write_str("alpn=")?;
                } else {
                    f.write_char(',')?;
                }
                for ch in v.as_ref() {
                    f.write_char(*ch as char)?;
                }
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct NoDefaultAlpn;

    impl NoDefaultAlpn {
        pub fn parse<'a, Octs: ?Sized>(
            _parser: &mut Parser<'a, Octs>
        ) -> Result<Self, ParseError> {
            Ok(Self)
        }
    }

    impl NoDefaultAlpn {
        fn compose<Target: OctetsBuilder + ?Sized>(
            &self, _target: &mut Target,
        ) -> Result<(), Target::AppendError> {
            Ok(())
        }
    }

    impl SvcbParam for NoDefaultAlpn {
        fn key(&self) -> SvcbParamKey {
            SvcbParamKey::NoDefaultAlpn
        }

        fn param_len(&self) -> u16 {
            0
        }
    }

    impl fmt::Display for NoDefaultAlpn {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("nodefaultalpn")
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct Port(u16);
    impl Port {
        pub fn new(port: u16) -> Self {
            Self(port)
        }

        pub fn parse<'a, Octs: AsRef<[u8]> + ?Sized>(
            parser: &mut Parser<'a, Octs>
        ) -> Result<Self, ParseError> {
            let port = u16::parse(parser)?;
            Ok(Self(port))
        }

        fn compose<Target: OctetsBuilder + ?Sized>(
            &self, target: &mut Target
        ) -> Result<(), Target::AppendError> {
            self.0.compose(target)
        }
    }

    impl SvcbParam for Port {
        fn key(&self) -> SvcbParamKey {
            SvcbParamKey::Port
        }

        fn param_len(&self) -> u16 {
            2
        }
    }

    impl fmt::Display for Port {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "port={}", self.0)
        }
    }

    // ECHConfigList: https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
    octets_wrapper!(Ech);

    impl<Octets> fmt::Display for Ech<Octets> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("ech")
        }
    }

    octets_wrapper!(Ipv4Hint, Ipv4HintIter);

    impl<OB: OctetsBuilder> Ipv4Hint<OB> {
        pub fn push(&mut self, addr: Ipv4Addr) -> Result<(), ShortBuf> {
            let octets = addr.octets();
            self.0.append_slice(octets.as_ref()).map_err(Into::into)
        }
    }

    impl<'a, Octs: AsRef<[u8]>> Iterator for Ipv4HintIter<'a, Octs> {
        type Item = Result<Ipv4Addr, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            let mut buf = [0u8; 4];
            //self.parser.check_len(buf.len())?;
            if let Err(e) = self.parser.parse_buf(&mut buf) {
                return Some(Err(e.into()));
            }
            Some(Ok(buf.into()))
        }
    }

    impl<Octs: AsRef<[u8]>> fmt::Display for Ipv4Hint<Octs> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            for (i, v) in self.iter().enumerate() {
                let v = v.map_err(|_| fmt::Error)?;
                if i == 0 {
                    write!(f, "ipv4hint={}", v)?;
                } else {
                    write!(f, ",{}", v)?;
                }
            }
            Ok(())
        }
    }

    octets_wrapper!(Ipv6Hint, Ipv6HintIter);

    impl<OB: OctetsBuilder> Ipv6Hint<OB> {
        pub fn push(&mut self, addr: Ipv6Addr) -> Result<(), ShortBuf> {
            let octets = addr.octets();
            self.0.append_slice(octets.as_ref()).map_err(Into::into)
        }
    }

    impl<'a, Octs: AsRef<[u8]>> Iterator for Ipv6HintIter<'a, Octs> {
        type Item = Result<Ipv6Addr, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            let mut buf = [0u8; 16];
            //self.parser.check_len(buf.len())?;
            if let Err(e) = self.parser.parse_buf(&mut buf) {
                return Some(Err(e.into()));
            }
            Some(Ok(buf.into()))
        }
    }

    impl<Octs: AsRef<[u8]>> fmt::Display for Ipv6Hint<Octs> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            for (i, v) in self.iter().enumerate() {
                let v = v.map_err(|_| fmt::Error)?;
                if i == 0 {
                    write!(f, "ipv6hint={}", v)?;
                } else {
                    write!(f, ",{}", v)?;
                }
            }
            Ok(())
        }
    }

    // contains an URL template: https://datatracker.ietf.org/doc/html/rfc6570
    octets_wrapper!(DohPath);

    impl<Octs: AsRef<[u8]>> fmt::Display for DohPath<Octs> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("dohpath=")?;
            for ch in self.0.as_ref() {
                f.write_char(*ch as char)?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct Unknown<Octs> {
        key: SvcbParamKey,
        val: Octs,
    }

    impl<Octs: AsRef<[u8]>> SvcbParam for Unknown<Octs> {
        fn key(&self) -> SvcbParamKey {
            self.key
        }

        fn param_len(&self) -> u16 {
            self.val.as_ref().len().try_into().expect("long param")
        }
    }

    impl<Octs> Unknown<Octs> {
        pub fn new(key: SvcbParamKey, val: Octs) -> Self {
            Self { key, val }
        }

        pub fn value(&self) -> &Octs {
            &self.val
        }
    }

    impl<Octs: AsRef<[u8]>> Unknown<Octs> {
        fn compose<Target: OctetsBuilder + ?Sized>(
            &self, target: &mut Target
        ) -> Result<(), Target::AppendError> {
            target.append_slice(self.val.as_ref())
        }
    }

    impl<Octs: AsRef<[u8]>> fmt::Display for Unknown<Octs> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.key())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::base::Dname;

    type Octets512 = Array<512>;

    // Test parser and composer with test vectors from appendix D
    #[test]
    fn test_vectors_alias() {
        let rdata =
            b"\x00\x00\
              \x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(0, svcb.priority);
        assert_eq!(
            "foo.example.com".parse::<Dname<Octets512>>().unwrap(),
            svcb.target
        );
        assert_eq!(0, svcb.params.len());

        // compose test
        let svcb_builder =
            Svcb::new(svcb.priority, svcb.target, Octets512::new());

        let mut buf = Octets512::new();
        svcb_builder.freeze().compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[test]
    fn test_vectors_port_only() {
        let rdata =
            b"\x00\x10\
              \x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\
              \x00\x03\
              \x00\x02\
              \x00\x35";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(16, svcb.priority);
        assert_eq!(
            "foo.example.com".parse::<Dname<Octets512>>().unwrap(),
            svcb.target
        );

        let mut param_iter = svcb.iter();
        let param = param_iter.next().unwrap().unwrap();
        assert_eq!(AllParams::from(param::Port::new(53)), param);
        assert_eq!(None, param_iter.next());

        // compose test
        let mut svcb_builder =
            Svcb::new(svcb.priority, svcb.target, Octets512::new());
        svcb_builder
            .push::<&[u8]>(param::Port::new(53).into())
            .unwrap();
        let mut buf = Octets512::new();
        svcb_builder.freeze().compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[test]
    fn test_vectors_unknown_param() {
        let rdata =
            b"\x00\x01\
              \x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\
              \x02\x9b\
              \x00\x05\
              \x68\x65\x6c\x6c\x6f";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(1, svcb.priority);
        assert_eq!(
            "foo.example.com".parse::<Dname<Octets512>>().unwrap(),
            svcb.target
        );

        let mut param_iter = svcb.iter();
        let r = param_iter.next();
        match r {
            Some(Ok(AllParams::Unknown(param))) => {
                assert_eq!(0x029b, param.key());
                assert_eq!(b"\x68\x65\x6c\x6c\x6f".as_ref(), *param.value(),);
            }
            _ => panic!("{:?}", r),
        }
        assert_eq!(None, param_iter.next());

        // compose test
        let mut svcb_builder =
            Svcb::new(svcb.priority, svcb.target, Octets512::new());
        svcb_builder
            .push(param::Unknown::new(0x029b.into(), b"hello").into())
            .unwrap();
        let mut buf = Octets512::new();
        svcb_builder.freeze().compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[test]
    fn test_vectors_unknown_param_quote() {
        let rdata =
            b"\x00\x01\
              \x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\
              \x02\x9b\
              \x00\x09\
              \x68\x65\x6c\x6c\x6f\xd2\x71\x6f\x6f";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(1, svcb.priority);
        assert_eq!(
            "foo.example.com".parse::<Dname<Octets512>>().unwrap(),
            svcb.target
        );

        let mut param_iter = svcb.iter();
        let r = param_iter.next();
        match r {
            Some(Ok(AllParams::Unknown(param))) => {
                assert_eq!(0x029b, param.key());
                assert_eq!(
                    b"\x68\x65\x6c\x6c\x6f\xd2\x71\x6f\x6f".as_ref(),
                    *param.value(),
                );
            }
            _ => panic!("{:?}", r),
        }
        assert_eq!(None, param_iter.next());

        // compose test
        let mut svcb_builder =
            Svcb::new(svcb.priority, svcb.target, Octets512::new());
        svcb_builder
            .push(
                param::Unknown::new(
                    0x029b.into(),
                    b"\x68\x65\x6c\x6c\x6f\xd2\x71\x6f\x6f",
                )
                .into(),
            )
            .unwrap();
        let mut buf = Octets512::new();
        svcb_builder.freeze().compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_vectors_ipv6hint() {
        let rdata =
            b"\x00\x01\
              \x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\
              \x00\x06\
              \x00\x20\
              \x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\
              \x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(1, svcb.priority);
        assert_eq!(
            "foo.example.com".parse::<Dname<Octets512>>().unwrap(),
            svcb.target
        );

        let mut param_iter = svcb.iter();
        let r = param_iter.next();
        match r {
            Some(Ok(AllParams::Ipv6Hint(param))) => {
                let mut iter = param.iter();
                assert_eq!(
                    "2001:db8::1",
                    format!("{}", iter.next().unwrap().unwrap()),
                );
                assert_eq!(
                    "2001:db8::53:1",
                    format!("{}", iter.next().unwrap().unwrap()),
                );
                assert_eq!(None, iter.next());
            }
            _ => panic!("{:?}", r),
        }
        assert_eq!(None, param_iter.next());

        // compose test
        let mut svcb_builder =
            Svcb::new(svcb.priority, svcb.target, Octets512::new());
        let mut ipv6_hint_builder = param::Ipv6Hint::new(Octets512::new());
        ipv6_hint_builder
            .push(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ]
                .into(),
            )
            .unwrap();
        ipv6_hint_builder
            .push(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x01,
                ]
                .into(),
            )
            .unwrap();
        svcb_builder
            .push(ipv6_hint_builder.freeze().into())
            .unwrap();
        let mut buf = Octets512::new();
        svcb_builder.freeze().compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_vectors_ipv6hint_v4mapped() {
        let rdata =
            b"\x00\x01\
              \x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\
              \x00\x06\
              \x00\x10\
              \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xc6\x33\x64\x64";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(1, svcb.priority);
        assert_eq!(
            "example.com".parse::<Dname<Octets512>>().unwrap(),
            svcb.target
        );

        let mut param_iter = svcb.iter();
        let r = param_iter.next();
        match r {
            Some(Ok(AllParams::Ipv6Hint(param))) => {
                let mut iter = param.iter();
                assert_eq!(
                    "::ffff:198.51.100.100",
                    format!("{}", iter.next().unwrap().unwrap()),
                );
                assert_eq!(None, iter.next());
            }
            _ => panic!("{:?}", r),
        }
        assert_eq!(None, param_iter.next());

        // compose test
        let mut svcb_builder =
            Svcb::new(svcb.priority, svcb.target, Octets512::new());
        let mut ipv6_hint_builder = param::Ipv6Hint::new(Octets512::new());
        ipv6_hint_builder
            .push(
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0xff, 0xff, 198, 51, 100, 100,
                ]
                .into(),
            )
            .unwrap();
        svcb_builder
            .push(ipv6_hint_builder.freeze().into())
            .unwrap();
        let mut buf = Octets512::new();
        svcb_builder.freeze().compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_vectors_key_sorting() {
        let rdata =
            b"\x00\x10\
              \x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\
              \x00\x00\
              \x00\x04\
              \x00\x01\
              \x00\x04\
              \x00\x01\
              \x00\x09\
              \x02\
              \x68\x32\
              \x05\
              \x68\x33\x2d\x31\x39\
              \x00\x04\
              \x00\x04\
              \xc0\x00\x02\x01";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(16, svcb.priority);
        assert_eq!(
            "foo.example.org".parse::<Dname<Octets512>>().unwrap(),
            svcb.target
        );

        let mut param_iter = svcb.iter();
        let r = param_iter.next();
        match r {
            Some(Ok(AllParams::Mandatory(keys))) => {
                let mut iter = keys.iter();
                assert_eq!(Some(Ok(SvcbParamKey::Alpn)), iter.next());
                assert_eq!(Some(Ok(SvcbParamKey::Ipv4Hint)), iter.next());
                assert_eq!(None, iter.next());
            }
            _ => panic!("{:?}", r),
        }

        let r = param_iter.next();
        match r {
            Some(Ok(AllParams::Alpn(names))) => {
                let mut iter = names.iter();
                assert_eq!(Some(Ok("h2".as_bytes())), iter.next());
                assert_eq!(Some(Ok("h3-19".as_bytes())), iter.next());
                assert_eq!(None, iter.next());
            }
            _ => panic!("{:?}", r),
        }

        let r = param_iter.next();
        match r {
            Some(Ok(AllParams::Ipv4Hint(hints))) => {
                let mut iter = hints.iter();
                assert_eq!(
                    "192.0.2.1",
                    format!("{}", iter.next().unwrap().unwrap()),
                );
                assert_eq!(None, iter.next());
            }
            _ => panic!("{:?}", r),
        }
        assert_eq!(None, param_iter.next());

        // compose test
        let mut mandatory_builder = param::Mandatory::new(Octets512::new());
        mandatory_builder.push(SvcbParamKey::Alpn).unwrap();
        mandatory_builder.push(SvcbParamKey::Ipv4Hint).unwrap();
        let mandatory = mandatory_builder.freeze();

        let mut alpn_builder = param::Alpn::new(Octets512::new());
        alpn_builder.push("h2").unwrap();
        alpn_builder.push("h3-19").unwrap();
        let alpn = alpn_builder.freeze();

        let mut ipv4_hint_builder = param::Ipv4Hint::new(Octets512::new());
        ipv4_hint_builder.push([192, 0, 2, 1].into()).unwrap();
        let ipv4_hint = ipv4_hint_builder.freeze();

        let mut svcb_builder =
            Svcb::new(svcb.priority, svcb.target, Octets512::new());
        svcb_builder.push(mandatory.into()).unwrap();
        svcb_builder.push(alpn.into()).unwrap();
        svcb_builder.push(ipv4_hint.into()).unwrap();

        let mut buf = Octets512::new();
        svcb_builder.freeze().compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[test]
    fn test_vectors_alpn_escape() {
        let rdata =
            b"\x00\x10\
              \x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\
              \x00\x01\
              \x00\x0c\
              \x08\
              \x66\x5c\x6f\x6f\x2c\x62\x61\x72\
              \x02\
              \x68\x32";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(16, svcb.priority);
        assert_eq!(
            "foo.example.org".parse::<Dname<Octets512>>().unwrap(),
            svcb.target
        );

        let mut param_iter = svcb.iter();
        let r = param_iter.next();
        match r {
            Some(Ok(AllParams::Alpn(names))) => {
                let mut iter = names.iter();
                assert_eq!(Some(Ok(br#"f\oo,bar"#.as_ref())), iter.next());
                assert_eq!(Some(Ok("h2".as_bytes())), iter.next());
                assert_eq!(None, iter.next());
            }
            _ => panic!("{:?}", r),
        }
        assert_eq!(None, param_iter.next());

        // compose test
        let mut svcb_builder =
            Svcb::new(svcb.priority, svcb.target, Octets512::new());

        let mut alpn_builder = param::Alpn::new(Octets512::new());
        alpn_builder.push(br#"f\oo,bar"#).unwrap();
        alpn_builder.push("h2").unwrap();
        let alpn = alpn_builder.freeze();

        svcb_builder.push(alpn.into()).unwrap();
        let mut buf = Octets512::new();
        svcb_builder.freeze().compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_representation() {
        use crate::base::iana::svcb::SVCB_PARAM_KEY_PRIVATE_RANGE_BEGIN;

        let mut mandatory_builder = param::Mandatory::new(Octets512::new());
        mandatory_builder.push(SvcbParamKey::Alpn).unwrap();
        mandatory_builder.push(SvcbParamKey::Ipv4Hint).unwrap();
        mandatory_builder
            .push(SVCB_PARAM_KEY_PRIVATE_RANGE_BEGIN.into())
            .unwrap();
        let mandatory = mandatory_builder.freeze();

        assert_eq!(
            "mandatory=alpn,ipv4hint,key65280",
            format!("{}", mandatory.for_slice())
        );

        let mut alpn_builder = param::Alpn::new(Octets512::new());
        alpn_builder.push("h2").unwrap();
        alpn_builder.push("h3-19").unwrap();
        assert_eq!(
            "alpn=h2,h3-19",
            format!("{}", alpn_builder.freeze().for_slice())
        );

        assert_eq!("nodefaultalpn", format!("{}", param::NoDefaultAlpn));

        assert_eq!(
            "ech",
            format!(
                "{}",
                param::Ech::new(Octets512::new()).freeze().for_slice()
            )
        );

        let mut ipv4_hint_builder = param::Ipv4Hint::new(Octets512::new());
        ipv4_hint_builder.push([192, 0, 2, 1].into()).unwrap();
        ipv4_hint_builder.push([192, 0, 2, 2].into()).unwrap();
        let ipv4_hint = ipv4_hint_builder.freeze();
        assert_eq!(
            "ipv4hint=192.0.2.1,192.0.2.2",
            format!("{}", ipv4_hint.for_slice())
        );
    }

    #[test]
    fn test_param_order() {
        let mut mandatory_builder = param::Mandatory::new(Octets512::new());
        mandatory_builder.push(SvcbParamKey::Alpn).unwrap();
        mandatory_builder.push(SvcbParamKey::Ipv4Hint).unwrap();
        let mandatory = mandatory_builder.freeze();

        let mut alpn_builder = param::Alpn::new(Octets512::new());
        alpn_builder.push("h2").unwrap();
        alpn_builder.push("h3-19").unwrap();
        let alpn = alpn_builder.freeze();

        let mut ipv4_hint_builder = param::Ipv4Hint::new(Octets512::new());
        ipv4_hint_builder.push([192, 0, 2, 1].into()).unwrap();
        let ipv4_hint = ipv4_hint_builder.freeze();

        let target: Dname<Octets512> = "example.com".parse().unwrap();
        let mut svcb_builder = Svcb::new(1, target, Octets512::new());

        // params are pushed out of order
        svcb_builder.push(ipv4_hint.into()).unwrap();
        svcb_builder.push(alpn.into()).unwrap();
        svcb_builder.push(mandatory.into()).unwrap();
        let svcb = svcb_builder.freeze();

        // unchecked compose
        let mut buf = Octets512::new();
        svcb.compose_unchecked(&mut buf).unwrap();
        let mut parser = Parser::from_ref(buf.as_ref());
        let parsed_svcb = Svcb::parse(&mut parser).unwrap();
        let mut iter = parsed_svcb.iter();
        assert_eq!(
            SvcbParamKey::Ipv4Hint,
            iter.next().unwrap().unwrap().key()
        );
        assert_eq!(SvcbParamKey::Alpn, iter.next().unwrap().unwrap().key());
        assert_eq!(
            SvcbParamKey::Mandatory,
            iter.next().unwrap().unwrap().key()
        );

        // checked compose
        let mut buf = Octets512::new();
        svcb.compose_rdata(&mut buf).unwrap();
        let mut parser = Parser::from_ref(buf.as_ref());
        let parsed_svcb = Svcb::parse(&mut parser).unwrap();
        let mut iter = parsed_svcb.iter();
        assert_eq!(
            SvcbParamKey::Mandatory,
            iter.next().unwrap().unwrap().key()
        );
        assert_eq!(SvcbParamKey::Alpn, iter.next().unwrap().unwrap().key());
        assert_eq!(
            SvcbParamKey::Ipv4Hint,
            iter.next().unwrap().unwrap().key()
        );
    }
}
