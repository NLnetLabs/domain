use bytes::BufMut;
use ::iana::{Class, Rtype};
use super::compose::{Compose, Compress, Compressor};
use super::error::ShortBuf;
use super::parse::{Parse, Parser};


//------------ Question ------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Question<N> {
    qname: N,
    qtype: Rtype,
    qclass: Class,
}

/// # Creation and Conversion
///
impl<N> Question<N> {
    pub fn new(qname: N, qtype: Rtype, qclass: Class) -> Self {
        Question { qname, qtype, qclass }
    }

    pub fn new_in(qname: N, qtype: Rtype) -> Self {
        Question { qname, qtype, qclass: Class::In }
    }
}


/// # Field Access
///
impl<N> Question<N> {
    pub fn qname(&self) -> &N {
        &self.qname
    }

    pub fn qtype(&self) -> Rtype {
        self.qtype
    }

    pub fn qclass(&self) -> Class {
        self.qclass
    }
}


//--- From

impl<N> From<(N, Rtype, Class)> for Question<N> {
    fn from((name, rtype, class): (N, Rtype, Class)) -> Self {
        Question::new(name, rtype, class)
    }
}

impl<N> From<(N, Rtype)> for Question<N> {
    fn from((name, rtype): (N, Rtype)) -> Self {
        Question::new(name, rtype, Class::In)
    }
}


//--- Parse, Compose, and Compress

impl<N: Parse> Parse for Question<N> {
    type Err = <N as Parse>::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Question::new(
            N::parse(parser)?,
            Rtype::parse(parser)?,
            Class::parse(parser)?
        ))
    }
}

impl<N: Compose> Compose for Question<N> {
    fn compose_len(&self) -> usize {
        self.qname.compose_len() + self.qtype.compose_len()
            + self.qclass.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.qname.compose(buf);
        self.qtype.compose(buf);
        self.qclass.compose(buf);
    }
}

impl<N: Compress> Compress for Question<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        self.qname.compress(buf)?;
        buf.compose(&self.qtype)?;
        buf.compose(&self.qclass)
    }
}

