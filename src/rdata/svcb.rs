// Implementation of SVCB RR type
// https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-08#section-8

use crate::base::iana::{Rtype, SvcbParamKey};
use crate::base::name::{ParsedDname, ToDname};
use crate::base::octets::{
    Compose, Octets512, OctetsBuilder, OctetsFrom, OctetsRef, Parse,
    ParseError, Parser, ShortBuf,
};
use crate::base::rdata::RtypeRecordData;
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
}

impl<O, OO, N, NN> OctetsFrom<$name<O, N>> for $name<OO, NN>
where
    OO: OctetsFrom<O>,
    NN: OctetsFrom<N>,
{
    fn octets_from(source: $name<O, N>) -> Result<Self, ShortBuf> {
        Ok($name::new(
            source.priority,
            NN::octets_from(source.target)?,
            OO::octets_from(source.params)?,
        ))
    }
}

impl<OB: OctetsBuilder, N> $name<OB, N> {
    /// Freeze the internal OctetsBuilder.
    pub fn freeze(self) -> $name<OB::Octets, N> {
        $name {
            priority: self.priority,
            target: self.target,
            params: self.params.freeze(),
            sorter: self.sorter,
        }
    }
}

impl<OB: OctetsBuilder + AsMut<[u8]>, N> $name<OB, N> {
    /// Push a parameter into the builder.
    pub fn push<O: AsRef<[u8]>>(
        &mut self,
        param: AllParams<O>,
    ) -> Result<(), ShortBuf> {
        let key = param.key().into();
        let off = self.params.len();
        param.compose(&mut self.params)?;
        let len = self.params.len() - off;
        self.sorter.insert(key, off as u16, len as u16)
    }
}

//--- Parse, ParseAll, Compose and Compress

impl<Ref: OctetsRef> Parse<Ref> for $name<Ref::Range, ParsedDname<Ref>> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let priority = u16::parse(parser)?;
        let target = ParsedDname::parse(parser)?;
        let len = parser.remaining();
        let params = parser.parse_octets(len)?;
        Ok(Self::new(priority, target, params))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        u16::skip(parser)?;
        ParsedDname::skip(parser)?;
        parser.advance_to_end();
        Ok(())
    }
}

impl<O: AsRef<[u8]>, N: Compose> Compose for $name<O, N> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.priority.compose(buf)?;
            self.target.compose(buf)?;

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
                buf.append_slice(slice)?;
            }

            Ok(())
        })
    }
}

impl<O: AsRef<[u8]>, N: Compose> $name<O, N> {
    /// Compose without checking for the order of parameters.
    pub fn compose_unchecked<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.priority.compose(buf)?;
            self.target.compose(buf)?;
            buf.append_slice(self.params.as_ref())
        })
    }
}

//--- RtypeRecordData

impl<O, N> RtypeRecordData for $name<O, N> {
    const RTYPE: Rtype = Rtype::$name;
}

impl<O: AsRef<[u8]>, N> $name<O, N> {
    pub fn iter(&self) -> ParamIter<&[u8]> {
        let parser = Parser::from_ref(self.params.as_ref());
        ParamIter { parser }
    }
}

//--- Display and Debug
impl<O, N> fmt::Display for $name<O, N>
where
    O: AsRef<[u8]>,
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
    O: AsRef<[u8]>,
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
    buf: Octets512,
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
pub struct ParamIter<Ref> {
    parser: Parser<Ref>,
}

impl<Ref> Iterator for ParamIter<Ref>
where
    Ref: OctetsRef,
{
    type Item = Result<AllParams<Ref::Range>, ParseError>;

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
        ($($name:ident($type:ty),)+) => {
            /// A enum to hold all the parameters.
            #[derive(Debug, Clone, PartialEq)]
            pub enum AllParams<Octets> {
                $($name($type)),+
            }

            impl<Octets> SvcbParam for AllParams<Octets> {
                fn key(&self) -> SvcbParamKey {
                    match self {
                        $(Self::$name(v) => v.key()),+
                    }
                }
            }

            impl<Ref: OctetsRef> Parse<Ref> for AllParams<Ref::Range> {
                fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
                    let key = parser.parse_u16()?.into();
                    let len = parser.parse_u16()?.into();
                    parser.parse_block(len, |parser| AllParams::parse_value(parser, key))
                }

                fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
                    u16::skip(parser)?;
                    let len = parser.parse_u16()?;
                    parser.advance(len.into())
                }
            }

            impl<O: AsRef<[u8]>> Compose for AllParams<O> {
                fn compose<T: OctetsBuilder + AsMut<[u8]>>(
                    &self,
                    target: &mut T,
                ) -> Result<(), ShortBuf> {
                    target.append_all(|buf| {
                        let key: u16 = self.key().into();
                        key.compose(buf)?;
                        buf.u16_len_prefixed(|buf| match self {
                            $(Self::$name(v) => v.compose(buf)),+
                        })
                    })
                }
            }

            $(impl<Octets> From<$type> for AllParams<Octets> {
                fn from(p: $type) -> Self {
                    AllParams::$name(p)
                }
            })+

            impl<O: OctetsRef> fmt::Display for AllParams<O> {
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
        Mandatory(Mandatory<Octets>),
        Alpn(Alpn<Octets>),
        NoDefaultAlpn(NoDefaultAlpn),
        Port(Port),
        Ech(Ech<Octets>),
        Ipv4Hint(Ipv4Hint<Octets>),
        Ipv6Hint(Ipv6Hint<Octets>),
        DohPath(DohPath<Octets>),
        Unknown(Unknown<Octets>),
    );

    /// Basic trait for SVCB parameters.
    pub trait SvcbParam {
        fn key(&self) -> SvcbParamKey;
    }

    impl<Ref: OctetsRef> AllParams<Ref> {
        fn parse_value(
            parser: &mut Parser<Ref>,
            key: SvcbParamKey,
        ) -> Result<AllParams<Ref::Range>, ParseError> {
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
            #[derive(Debug, Clone, PartialEq)]
            pub struct $name<Octets>(Octets);
            impl<Ref: OctetsRef> Parse<Ref> for $name<Ref::Range> {
                fn parse(
                    parser: &mut Parser<Ref>,
                ) -> Result<Self, ParseError> {
                    //let len = u16::parse(parser)?;
                    //let data = parser.parse_octets(len.into())?;
                    let data = parser.parse_octets(parser.remaining())?;
                    Ok(Self(data))
                }

                fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
                    //u16::skip(parser)?;
                    parser.advance_to_end();
                    Ok(())
                }
            }

            impl<O: AsRef<[u8]>> Compose for $name<O> {
                fn compose<T: OctetsBuilder + AsMut<[u8]>>(
                    &self,
                    target: &mut T,
                ) -> Result<(), ShortBuf> {
                    // target.append_all(|buf| {
                    //     let len = self.0.as_ref().len() as u16;
                    //     len.compose(buf)?;
                    // })
                    target.append_slice(self.0.as_ref())
                }
            }

            impl<O> SvcbParam for $name<O> {
                fn key(&self) -> SvcbParamKey {
                    SvcbParamKey::$name
                }
            }
            impl<Octets> $name<Octets> {
                /// Create a new parameter from octets.
                pub fn new(o: Octets) -> Self {
                    Self(o)
                }
            }
            impl<OB: OctetsBuilder> $name<OB> {
                /// Freeze the internal OctetsBuilder.
                pub fn freeze(self) -> $name<OB::Octets> {
                    $name(self.0.freeze())
                }
            }

            impl<Octets> $name<Octets> {
                pub fn for_ref(&self) -> $name<&Octets> {
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

            impl<Octets: AsRef<T>, T> AsRef<T> for $name<Octets> {
                fn as_ref(&self) -> &T {
                    self.0.as_ref()
                }
            }

            impl<O, OO> OctetsFrom<$name<O>> for $name<OO>
            where
                OO: OctetsFrom<O>,
            {
                fn octets_from(source: $name<O>) -> Result<Self, ShortBuf> {
                    Ok($name::new(OO::octets_from(source.0)?))
                }
            }
        };
        ($name:ident, $iter:ident) => {
            octets_wrapper!($name);

            impl<Ref: OctetsRef> $name<Ref> {
                /// Iterate over the internal items.
                pub fn iter(&self) -> $iter<Ref> {
                    let parser = Parser::from_ref(self.0);
                    $iter { parser }
                }
            }

            /// An iterator type to parse the internal items.
            pub struct $iter<Ref: OctetsRef> {
                parser: Parser<Ref>,
            }
        };
    }

    octets_wrapper!(Mandatory, MandatoryIter);

    impl<OB: OctetsBuilder + AsMut<[u8]>> Mandatory<OB> {
        pub fn push(&mut self, key: SvcbParamKey) -> Result<(), ShortBuf> {
            u16::from(key).compose(&mut self.0)
        }
    }

    impl<Ref> Iterator for MandatoryIter<Ref>
    where
        Ref: OctetsRef,
    {
        type Item = Result<SvcbParamKey, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            Some(self.parser.parse_u16().map(|v| v.into()))
        }
    }

    impl<Ref: OctetsRef> fmt::Display for Mandatory<Ref> {
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

    impl<OB: OctetsBuilder + AsMut<[u8]>> Alpn<OB> {
        pub fn push<O: AsRef<[u8]>>(
            &mut self,
            name: O,
        ) -> Result<(), ShortBuf> {
            self.0.append_all(|buf| {
                let name = name.as_ref();
                let len: u8 = name.len().try_into().map_err(|_| ShortBuf)?;
                len.compose(buf)?;
                buf.append_slice(name)
            })
        }
    }

    impl<Ref: OctetsRef> Iterator for AlpnIter<Ref>
    where
        Ref: OctetsRef,
    {
        type Item = Result<Ref::Range, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            Some(
                self.parser
                    .parse_u8()
                    .and_then(|len| self.parser.parse_octets(len.into())),
            )
        }
    }

    impl<Ref: OctetsRef> fmt::Display for Alpn<Ref> {
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

    #[derive(Debug, Clone, PartialEq)]
    pub struct NoDefaultAlpn;

    impl<Ref: OctetsRef> Parse<Ref> for NoDefaultAlpn {
        fn parse(_parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
            Ok(Self)
        }

        fn skip(_parser: &mut Parser<Ref>) -> Result<(), ParseError> {
            Ok(())
        }
    }

    impl Compose for NoDefaultAlpn {
        fn compose<T: OctetsBuilder + AsMut<[u8]>>(
            &self,
            _target: &mut T,
        ) -> Result<(), ShortBuf> {
            Ok(())
        }
    }

    impl SvcbParam for NoDefaultAlpn {
        fn key(&self) -> SvcbParamKey {
            SvcbParamKey::NoDefaultAlpn
        }
    }

    impl fmt::Display for NoDefaultAlpn {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("nodefaultalpn")
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Port(u16);
    impl Port {
        pub fn new(port: u16) -> Self {
            Self(port)
        }
    }
    impl<Ref: OctetsRef> Parse<Ref> for Port {
        fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
            let port = u16::parse(parser)?;
            Ok(Self(port))
        }

        fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
            u16::skip(parser)?;
            Ok(())
        }
    }

    impl Compose for Port {
        fn compose<T: OctetsBuilder + AsMut<[u8]>>(
            &self,
            target: &mut T,
        ) -> Result<(), ShortBuf> {
            self.0.compose(target)
        }
    }

    impl SvcbParam for Port {
        fn key(&self) -> SvcbParamKey {
            SvcbParamKey::Port
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
            self.0.append_slice(octets.as_ref())
        }
    }

    impl<Ref> Iterator for Ipv4HintIter<Ref>
    where
        Ref: OctetsRef,
    {
        type Item = Result<Ipv4Addr, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            let mut buf = [0u8; 4];
            //self.parser.check_len(buf.len())?;
            if let Err(e) = self.parser.parse_buf(&mut buf) {
                return Some(Err(e));
            }
            Some(Ok(buf.into()))
        }
    }

    impl<Ref: OctetsRef> fmt::Display for Ipv4Hint<Ref> {
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
            self.0.append_slice(octets.as_ref())
        }
    }

    impl<Ref> Iterator for Ipv6HintIter<Ref>
    where
        Ref: OctetsRef,
    {
        type Item = Result<Ipv6Addr, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.parser.remaining() == 0 {
                return None;
            }

            let mut buf = [0u8; 16];
            //self.parser.check_len(buf.len())?;
            if let Err(e) = self.parser.parse_buf(&mut buf) {
                return Some(Err(e));
            }
            Some(Ok(buf.into()))
        }
    }

    impl<Ref: OctetsRef> fmt::Display for Ipv6Hint<Ref> {
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

    impl<Ref: OctetsRef> fmt::Display for DohPath<Ref> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("dohpath=")?;
            for ch in self.0.as_ref() {
                f.write_char(*ch as char)?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Unknown<Octets> {
        key: SvcbParamKey,
        val: Octets,
    }

    impl<Octets> SvcbParam for Unknown<Octets> {
        fn key(&self) -> SvcbParamKey {
            self.key
        }
    }

    impl<Octets> Unknown<Octets> {
        pub fn new(key: SvcbParamKey, val: Octets) -> Self {
            Self { key, val }
        }

        pub fn value(&self) -> &Octets {
            &self.val
        }
    }

    impl<O: AsRef<[u8]>> Compose for Unknown<O> {
        fn compose<T: OctetsBuilder + AsMut<[u8]>>(
            &self,
            target: &mut T,
        ) -> Result<(), ShortBuf> {
            target.append_slice(self.val.as_ref())
        }
    }

    impl<Ref: OctetsRef> fmt::Display for Unknown<Ref> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.key())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::base::{octets::Octets512, Dname};

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
        svcb_builder.freeze().compose(&mut buf).unwrap();
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
        svcb_builder.freeze().compose(&mut buf).unwrap();
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
        svcb_builder.freeze().compose(&mut buf).unwrap();
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
        svcb_builder.freeze().compose(&mut buf).unwrap();
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
        svcb_builder.freeze().compose(&mut buf).unwrap();
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
        svcb_builder.freeze().compose(&mut buf).unwrap();
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
        svcb_builder.freeze().compose(&mut buf).unwrap();
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
        svcb_builder.freeze().compose(&mut buf).unwrap();
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
        svcb.compose(&mut buf).unwrap();
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
